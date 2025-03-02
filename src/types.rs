#![allow(non_camel_case_types)]

use std::ffi::{c_char, c_int, c_long, c_short, c_uchar, c_uint, c_ulong, c_ushort};

// pub type s128 = __s128;
// pub type u128 = __u128;

// pub type __kernel_dev_t = u32;

// pub type fd_set = __kernel_fd_set;
// pub type dev_t = __kernel_dev_t;
// pub type ino_t = __kernel_ulong_t;
// pub type mode_t = __kernel_mode_t;
pub type umode_t = c_ushort;
pub type nlink_t = u32;
pub type off_t = c_long;
// pub type daddr_t = __kernel_daddr_t;
// pub type key_t = __kernel_key_t;
// pub type suseconds_t = __kernel_suseconds_t;
// pub type timer_t = __kernel_timer_t;
// pub type clockid_t = __kernel_clockid_t;
// pub type mqd_t = __kernel_mqd_t;

pub type uid_t = c_uint;
pub type gid_t = c_uint;
// pub type uid16_t = __kernel_uid16_t;
// pub type gid16_t = __kernel_gid16_t;

pub type uintptr_t = c_ulong;
pub type intptr_t = c_long;

pub type size_t = c_ulong;
pub type pid_t = c_int;

pub type ssize_t = c_long;

pub type u_char = c_uchar;
pub type u_short = c_ushort;
pub type u_int = c_uint;
pub type u_long = c_ulong;
pub type sa_family_t = c_ushort;


#[repr(C)]
#[derive(Debug)]
pub struct sockaddr {
	pub sa_family: sa_family_t,	/* address family, AF_xxx	*/
	sa_data_min: [c_char; 14],		/* Minimum 14 bytes of protocol address	*/
}


#[repr(C)]
#[derive(Debug)]
pub struct Stat {
	pub st_dev: c_uint,
	pub st_ino: c_uint,
	pub st_mode: c_uint,
	pub st_nlink: c_uint,
	pub st_uid: c_uint,
	pub st_gid: c_uint,
	pub st_rdev: c_uint,
	pub st_size: c_long,
	pub st_atime: c_ulong,
	pub st_mtime: c_ulong,
	pub st_ctime: c_ulong,
	pub st_blksize: c_uint,
	pub st_blocks: c_uint,
	pub st_flags: c_uint,
	pub st_gen: c_uint,
}

#[repr(C)]
#[derive(Debug)]
pub struct Pollfd {
	pub fd: c_int,
	pub events: c_short,
	pub revents: c_short,
}
