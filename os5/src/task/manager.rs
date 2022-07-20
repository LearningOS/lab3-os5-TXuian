//! Implementation of [`TaskManager`]
//!
//! It is only used to manage processes and schedule process based on ready queue.
//! Other CPU process monitoring functions are in Processor.

use super::TaskControlBlock;
use crate::sync::UPSafeCell;
use alloc::collections::{VecDeque, BTreeSet, BTreeMap};
use alloc::sync::Arc;
use alloc::vec::{Vec};
use lazy_static::*;

pub struct TaskManager {
    ready_set: BTreeMap<usize, Vec<Arc<TaskControlBlock>>>,
}

// YOUR JOB: FIFO->Stride
/// A simple FIFO scheduler.
impl TaskManager {
    pub fn new() -> Self {
        Self {
            ready_set: BTreeMap::new(),
        }
    }
    /// Add process back to ready queue
    pub fn add(&mut self, task: Arc<TaskControlBlock>) {
        let this_pass = task.inner_exclusive_access().pass;
        match self.ready_set.get_mut(&this_pass) {
            Some(tcb_vec) => {
                tcb_vec.push(task);
            },
            None => {
                self.ready_set.insert(this_pass, Vec::from([task]));
            },
        }
    }
    /// Take a process out of the ready queue
    pub fn fetch(&mut self) -> Option<Arc<TaskControlBlock>> {
        match self.ready_set.pop_first() {
            Some((key, mut value)) => {
                let task = value.pop();
                if !value.is_empty() {
                    self.ready_set.insert(key, value);
                }
                return task;
            },
            None => {
                None
            },
        }
    }
}

lazy_static! {
    /// TASK_MANAGER instance through lazy_static!
    pub static ref TASK_MANAGER: UPSafeCell<TaskManager> =
        unsafe { UPSafeCell::new(TaskManager::new()) };
}

pub fn add_task(task: Arc<TaskControlBlock>) {
    TASK_MANAGER.exclusive_access().add(task);
}

pub fn fetch_task() -> Option<Arc<TaskControlBlock>> {
    TASK_MANAGER.exclusive_access().fetch()
}
