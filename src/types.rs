#![allow(non_camel_case_types)]

use std::ffi::{c_int, c_long, c_uchar, c_uint, c_ulong, c_ushort};

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

// pub type uid_t = __kernel_uid32_t;
// pub type gid_t = __kernel_gid32_t;
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
