
/// This module contains all the syscalls needed with their signatures and data types.<br>
/// This is not an implementation of syscalls in rust.<br>
/// This is just linking the available syscalls using ffi signatures<br>
pub mod syscalls;

/// This module contains all the type we needed for a syscall functions work<br>
/// it will not conatain any extra types<br>
pub mod types;

/// This is a test module for this project
mod test;