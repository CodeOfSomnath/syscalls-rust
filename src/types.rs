#![allow(non_camel_case_types)]

use std::ffi::{c_char, c_int, c_long, c_short, c_uchar, c_uint, c_ulong, c_ushort};


pub type umode_t = c_ushort;
pub type nlink_t = u32;
pub type off_t = c_long;

pub type uid_t = c_uint;
pub type gid_t = c_uint;

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
pub type mode_t = c_ushort;


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
