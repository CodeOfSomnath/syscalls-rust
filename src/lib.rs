
/// This module contains all the syscalls needed with their signatures and data types 
/// This is not an implementation of syscalls in rust. This is just linking the available syscalls using ffi signatures
pub mod syscalls;

/// This module contains all the type we needed for a syscall functions work
/// it will not conatain any extra types 
pub mod types;

/// This is a test module for this project
mod test;