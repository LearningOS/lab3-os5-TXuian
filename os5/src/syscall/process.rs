//! Process management syscalls

use core::cmp::max;

use crate::loader::get_app_data_by_name;
use crate::mm::{translated_refmut, translated_str, MemorySet, VirtAddr, 
    KERNEL_SPACE, MapPermission, PageTable, StepByOne};
use crate::sync::UPSafeCell;
use crate::task::{
    add_task, current_task, current_user_token, exit_current_and_run_next,
    suspend_current_and_run_next, TaskStatus, set_current_task_running_time, 
    current_task_info, pid_alloc, KernelStack, TaskControlBlock, TaskContext,
    TaskControlBlockInner, current_task_insert_mm, current_task_unmap_area, set_current_task_priority,
};
use crate::trap::{trap_handler, TrapContext};
use crate::timer::get_time_us;
use alloc::sync::Arc;
use alloc::vec::Vec;
use crate::config::{MAX_SYSCALL_NUM, TRAP_CONTEXT, PAGE_SIZE, BIG_STRIDE};

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

#[derive(Clone, Copy)]
pub struct TaskInfo {
    pub status: TaskStatus,
    pub syscall_times: [u32; MAX_SYSCALL_NUM],
    pub time: usize,
}

pub fn sys_exit(exit_code: i32) -> ! {
    debug!("[kernel] Application exited with code {}", exit_code);
    exit_current_and_run_next(exit_code);
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    suspend_current_and_run_next();
    0
}

pub fn sys_getpid() -> isize {
    current_task().unwrap().pid.0 as isize
}

/// Syscall Fork which returns 0 for child process and child_pid for parent process
pub fn sys_fork() -> isize {
    let current_task = current_task().unwrap();
    let new_task = current_task.fork();
    let new_pid = new_task.pid.0;
    // modify trap context of new_task, because it returns immediately after switching
    let trap_cx = new_task.inner_exclusive_access().get_trap_cx();
    // we do not have to move to next instruction since we have done it before
    // for child process, fork returns 0
    trap_cx.x[10] = 0;
    // add new task to scheduler
    add_task(new_task);
    new_pid as isize
}

/// Syscall Exec which accepts the elf path
pub fn sys_exec(path: *const u8) -> isize {
    let token = current_user_token();
    let path = translated_str(token, path);
    if let Some(data) = get_app_data_by_name(path.as_str()) {
        let task = current_task().unwrap();
        task.exec(data);
        0
    } else {
        -1
    }
}

/// If there is not a child process whose pid is same as given, return -1.
/// Else if there is a child process but it is still running, return -2.
pub fn sys_waitpid(pid: isize, exit_code_ptr: *mut i32) -> isize {
    let task = current_task().unwrap();
    // find a child process

    // ---- access current TCB exclusively
    let mut inner = task.inner_exclusive_access();
    if !inner
        .children
        .iter()
        .any(|p| pid == -1 || pid as usize == p.getpid())
    {
        return -1;
        // ---- release current PCB
    }
    let pair = inner.children.iter().enumerate().find(|(_, p)| {
        // ++++ temporarily access child PCB lock exclusively
        p.inner_exclusive_access().is_zombie() && (pid == -1 || pid as usize == p.getpid())
        // ++++ release child PCB
    });
    if let Some((idx, _)) = pair {
        let child = inner.children.remove(idx);
        // confirm that child will be deallocated after removing from children list
        assert_eq!(Arc::strong_count(&child), 1);
        let found_pid = child.getpid();
        // ++++ temporarily access child TCB exclusively
        let exit_code = child.inner_exclusive_access().exit_code;
        // ++++ release child PCB
        *translated_refmut(inner.memory_set.token(), exit_code_ptr) = exit_code;
        found_pid as isize
    } else {
        -2
    }
    // ---- release current PCB lock automatically
}

// YOUR JOB: 引入虚地址后重写 sys_get_time
pub fn sys_get_time(_ts: *mut TimeVal, _tz: usize) -> isize {
    debug!("run sys_get_time.");
    let _us = get_time_us();
    let _us = get_time_us();
    set_current_task_running_time(_us / 1_000);
    let true_ts = translated_refmut(current_user_token(), _ts);
    // info!("get & mut ts");
    (*true_ts).sec = _us /1_000_000;
    (*true_ts).usec = _us % 1_000_000;
    0
}

// YOUR JOB: 引入虚地址后重写 sys_task_info
pub fn sys_task_info(ti: *mut TaskInfo) -> isize {
    // call task control block for info
    info!("run sys_task_info.");
    match current_task_info() {
        Some((s, st, t)) => {
            let true_task_info = translated_refmut(current_user_token(), ti);
            (*true_task_info).status = s;
            (*true_task_info).syscall_times = st;
            (*true_task_info).time = t;
            0
        },
        None => -1,
    }
}

// YOUR JOB: 实现sys_set_priority，为任务添加优先级
pub fn sys_set_priority(_prio: isize) -> isize {
    if _prio < 2 {return -1;}
    return set_current_task_priority(_prio);
}

// YOUR JOB: 扩展内核以实现 sys_mmap 和 sys_munmap
pub fn sys_mmap(_start: usize, _len: usize, _port: usize) -> isize {
    if (_port & !0x7 != 0) || (_port & 0x7 == 0) {
        return -1;
    }
    if _start % PAGE_SIZE != 0 {
        return -1;
    }
    // get permission
    let mut mm_perm = MapPermission::U;
    if (_port & 0x01) != 0x00 {
        mm_perm |= MapPermission::R;
    }
    if (_port & 0x02) != 0x00 {
        mm_perm |= MapPermission::W;
    }
    if (_port & 0x04) != 0x00 {
        mm_perm |= MapPermission::X;
    }
    // virt range that should allocate
    let start_va = VirtAddr::from(_start);
    let end_va = VirtAddr::from(_start + _len);
    // check if area is allocated
    let page_table = PageTable::from_token(current_user_token());
    let mut cur_vpn = start_va.floor();
    let end_vpn = end_va.ceil(); 
    while cur_vpn.0 < end_vpn.0 {
        if let Some(entry) = page_table.translate(cur_vpn) {
            if entry.is_valid() {
                return -1;
            }
        }
        cur_vpn.step();
    }
    // insert map_area to user's memset
    current_task_insert_mm(start_va, end_va, mm_perm);
    0
}

pub fn sys_munmap(_start: usize, _len: usize) -> isize {
    // virt range that should unallocate
    let start_va = VirtAddr::from(_start);
    let end_va = VirtAddr::from(_start + _len);
    // check if an area is unallocated
    let page_table = PageTable::from_token(current_user_token());
    let mut cur_vpn = start_va.floor();
    let end_vpn = end_va.ceil();
    while cur_vpn.0 <= end_vpn.0 {
        match page_table.translate(cur_vpn) {
            None => { return -1; }
            Some(entry) => {
                if !entry.is_valid() {
                    return -1;
                }
            }
        }
        cur_vpn.step();
    }
    // get map_area of user
    current_task_unmap_area(start_va, end_va);
    0
}

//
// YOUR JOB: 实现 sys_spawn 系统调用
// ALERT: 注意在实现 SPAWN 时不需要复制父进程地址空间，SPAWN != FORK + EXEC 
pub fn sys_spawn(_path: *const u8) -> isize {
    // reference to initproc
    // get complete file path
    let token = current_user_token();
    let path = translated_str(token, _path);
    if let Some(elf_data) = get_app_data_by_name(path.as_str()) {
        // ***********
        let (memory_set, user_sp, entry_point) = MemorySet::from_elf(elf_data);
        let trap_cx_ppn = memory_set
            .translate(VirtAddr::from(TRAP_CONTEXT).into())
            .unwrap()
            .ppn();
        // alloc a pid and a kernel stack in kernel space
        let pid_handle = pid_alloc();
        let kernel_stack = KernelStack::new(&pid_handle);
        let kernel_stack_top = kernel_stack.get_top();
        // push a task context which goes to trap_return to the top of kernel stack
        let new_task = Arc::new(TaskControlBlock {
            pid: pid_handle,
            kernel_stack,
            inner: unsafe {
                UPSafeCell::new(TaskControlBlockInner {
                    trap_cx_ppn,
                    base_size: user_sp,
                    task_cx: TaskContext::goto_trap_return(kernel_stack_top),
                    task_status: TaskStatus::Ready,
                    memory_set,
                    parent: None,
                    children: Vec::new(),
                    exit_code: 0,
                    first_run_time: 0,
                    current_time: 0,
                    syscall_times: [0; MAX_SYSCALL_NUM],
                    stride: max(2, BIG_STRIDE / 16),
                    pass: 0,
                })
            },
        });
        // prepare TrapContext in user space
        let trap_cx = new_task.inner_exclusive_access().get_trap_cx();
        *trap_cx = TrapContext::app_init_context(
            entry_point,
            user_sp,
            KERNEL_SPACE.exclusive_access().token(),
            kernel_stack_top,
            trap_handler as usize,
        );
        // ***********
        // let new_task = Arc::new(TaskControlBlock::new(elf_data));
        // already set mem_set, task_control_block, and trap_cx in new
        let new_pid = new_task.getpid();
        // set child return
        (*trap_cx).x[10] = 0;
        add_task(new_task);
        new_pid as isize
    } else {
        -1
    }
}
