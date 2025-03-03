#![cfg(test)]

use crate::syscalls::arch64::*;


#[test]
pub fn test_fork() {
    let pid = unsafe { fork() };
    println!("fork pid: {}", pid);
}


#[test]
pub fn test_vfork() {
    // let pid = unsafe { vfork() };
    // println!("vfork pid: {}", pid);
}