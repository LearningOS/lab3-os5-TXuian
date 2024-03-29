#![no_std]
#![no_main]

#[macro_use]
extern crate user_lib;

use user_lib::{exec, fork, wait, yield_};

#[no_mangle]
fn main() -> i32 {
    if fork() == 0 {  // child process of initproc, which is shell
        exec("ch5b_user_shell\0", &[0 as *const u8]);
    } else {  // initproc, release zombie process
        loop {
            let mut exit_code: i32 = 0;
            // waiting for a unreleased proc
            let pid = wait(&mut exit_code);
            if pid == -1 {
                yield_();
                continue;
            }
            println!(
                "[initproc] Released a zombie process, pid={}, exit_code={}",
                pid, exit_code,
            );
        }
    }
    0
}
