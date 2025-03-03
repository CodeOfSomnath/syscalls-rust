//// This module contains all the syscalls needed with their signatures and data types 
//// This is not an implementation of syscalls in rust. This is just linking the available syscalls using ffi signatures


/// This module supports all the 64 bit arch syscalls
#[cfg(feature = "arch64")]
pub mod arch64; // x86 64 bit, x86-64 abi



// This is a sample documentation for all the function donot change it here
// copy and change according to functions
 
// / read() attempts to read up to count bytes from file descriptor fd
// / into the buffer starting at buf.<br>
// / #### RETURN VALUE
// / On success, the number of bytes read is returned (zero indicates
// / end of file), and the file position is advanced by this number.
// / #### ERRORS
// / EAGAIN(35), EBADF(9), EFAULT(14), EINTR(4), EINVAL(22), EIO(5), EISDIR(21), etc.
// / #### Link
// / Read the docs
// / [here](https://man7.org/linux/man-pages/man2/read.2.html)
