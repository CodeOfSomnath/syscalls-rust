//// This module contains all the syscalls needed with their signatures and data types 
//// This is not an implementation of syscalls in rust. This is just linking the available syscalls using ffi signatures


/// This module supports all the 64 bit arch syscalls
#[cfg(feature = "arch64")]
pub mod arch64; // x86 64 bit, x86-64 abi

