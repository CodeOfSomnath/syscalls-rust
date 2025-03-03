#![cfg(test)]

use crate::syscalls::arch64::*;

#[test]
pub fn test_fork() {
    unsafe {
        fork();
    }
}

// #[test]
// pub fn test_vfork() {
//     // let pid = unsafe { vfork() };
//     // println!("vfork pid: {}", pid);
// }

#[test]
pub fn test_umask() {
    unsafe { umask(0777); }
}
