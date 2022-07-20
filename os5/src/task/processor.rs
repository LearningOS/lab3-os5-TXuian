//! Implementation of [`Processor`] and Intersection of control flow
//!
//! Here, the continuous operation of user apps in CPU is maintained,
//! the current running state of CPU is recorded,
//! and the replacement and transfer of control flow of different applications are executed.



use core::cmp::max;

use super::__switch;
use super::{fetch_task, TaskStatus};
use super::{TaskContext, TaskControlBlock};
use crate::config::{MAX_SYSCALL_NUM, BIG_STRIDE};
use crate::mm::{VirtAddr, MapPermission};
use crate::sync::UPSafeCell;
use crate::timer::get_time_us;
use crate::trap::TrapContext;
use alloc::sync::Arc;
use lazy_static::*;

/// Processor management structure
pub struct Processor {
    /// The task currently executing on the current processor
    current: Option<Arc<TaskControlBlock>>,
    /// The basic control flow of each core, helping to select and switch process
    idle_task_cx: TaskContext,
}

impl Processor {
    pub fn new() -> Self {
        Self {
            current: None,
            idle_task_cx: TaskContext::zero_init(),
        }
    }
    fn get_idle_task_cx_ptr(&mut self) -> *mut TaskContext {
        &mut self.idle_task_cx as *mut _
    }
    pub fn take_current(&mut self) -> Option<Arc<TaskControlBlock>> {
        self.current.take()
    }
    pub fn current(&self) -> Option<Arc<TaskControlBlock>> {
        self.current.as_ref().map(|task| Arc::clone(task))
    }
}

lazy_static! {
    /// PROCESSOR instance through lazy_static!
    pub static ref PROCESSOR: UPSafeCell<Processor> = unsafe { UPSafeCell::new(Processor::new()) };
}

/// The main part of process execution and scheduling
///
/// Loop fetch_task to get the process that needs to run,
/// and switch the process through __switch
pub fn run_tasks() {
    loop {
        let mut processor = PROCESSOR.exclusive_access();
        if let Some(task) = fetch_task() {
            let idle_task_cx_ptr = processor.get_idle_task_cx_ptr();
            // access coming task TCB exclusively
            let mut task_inner = task.inner_exclusive_access();
            let next_task_cx_ptr = &task_inner.task_cx as *const TaskContext;
            task_inner.task_status = TaskStatus::Running;
            debug!("task with pass {:?} is running.", task_inner.pass);
            // set running time
            let current_time = get_time_us() / 1_000;
            if task_inner.first_run_time == 0 {
                task_inner.first_run_time = current_time;
            }
            task_inner.current_time = current_time;
            // update pass
            task_inner.pass += task_inner.stride;
            // ****set running time done
            drop(task_inner);
            // release coming task TCB manually
            processor.current = Some(task);
            // release processor manually
            drop(processor);
            unsafe {
                __switch(idle_task_cx_ptr, next_task_cx_ptr);
            }
        }
    }
}

/// Get current task through take, leaving a None in its place
pub fn take_current_task() -> Option<Arc<TaskControlBlock>> {
    PROCESSOR.exclusive_access().take_current()
}

/// Get a copy of the current task
pub fn current_task() -> Option<Arc<TaskControlBlock>> {
    PROCESSOR.exclusive_access().current()
}

/// Get token of the address space of current task
pub fn current_user_token() -> usize {
    let task = current_task().unwrap();
    let token = task.inner_exclusive_access().get_user_token();
    token
}

/// Get the mutable reference to trap context of current task
pub fn current_trap_cx() -> &'static mut TrapContext {
    current_task()
        .unwrap()
        .inner_exclusive_access()
        .get_trap_cx()
}

/// Set current time for current task
pub fn set_current_task_running_time(current_time: usize) {
    let processor = PROCESSOR.exclusive_access();
    if let Some(current_task) = processor.current() {
        current_task.inner_exclusive_access().current_time = current_time;
    } // skip when there is not task running
}

pub fn set_current_task_syscall_times(syscall_id: usize) {
    let processor = PROCESSOR.exclusive_access();
    if let Some(current_task) = processor.current() {
        current_task.inner_exclusive_access().syscall_times[syscall_id] += 1;
    }// skip when there is not task running
}

pub fn set_current_task_priority(prio: isize) -> isize{
    let prio = max(1, prio);
    let processor = PROCESSOR.exclusive_access();
    if let Some(current_task) = processor.current() {
        let stride = max(2, BIG_STRIDE / (prio as usize));
        current_task.inner_exclusive_access().stride = stride;
        return prio;
    }// skip when there is not task running
    return -1;
}

pub fn current_task_info() -> Option<(TaskStatus, [u32; MAX_SYSCALL_NUM], usize)> {
    let processor = PROCESSOR.exclusive_access();
    match processor.current() {
        Some(current_task) => {
            let current_task_inner = current_task.inner_exclusive_access();
            Some((
                current_task_inner.task_status,
                current_task_inner.syscall_times,
                current_task_inner.current_time - current_task_inner.first_run_time
            ))
        },
        None => None
    }
}

pub fn current_task_insert_mm(start_va: VirtAddr, end_va: VirtAddr, permission: MapPermission) {
    let processor = PROCESSOR.exclusive_access();
    if let Some(current_task) = processor.current() {
        let current_mset = 
            &mut current_task.inner_exclusive_access()
                .memory_set;
        current_mset.insert_framed_area(start_va, end_va, permission)
    }
}

pub fn current_task_unmap_area(start_va: VirtAddr, end_va: VirtAddr) {
    let processor = PROCESSOR.exclusive_access();
    if let Some(current_task) = processor.current() {
        let current_mset = 
            &mut current_task.inner_exclusive_access()
                .memory_set;
        current_mset.delete_framed_area(start_va, end_va)
    }
}

/// Return to idle control flow for new scheduling
pub fn schedule(switched_task_cx_ptr: *mut TaskContext) {
    let mut processor = PROCESSOR.exclusive_access();
    let idle_task_cx_ptr = processor.get_idle_task_cx_ptr();
    drop(processor);
    unsafe {
        __switch(switched_task_cx_ptr, idle_task_cx_ptr);
    }
}
