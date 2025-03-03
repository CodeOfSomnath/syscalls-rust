#![cfg(feature = "arch64")]

use std::ffi::*;
use crate::types::*;





unsafe extern "system" {
 
    /// read() attempts to read up to count bytes from file descriptor fd
    /// into the buffer starting at buf.<br>
    /// #### RETURN VALUE
    /// On success, the number of bytes read is returned (zero indicates
    /// end of file), and the file position is advanced by this number.
    /// #### ERRORS
    /// EAGAIN(35), EBADF(9), EFAULT(14), EINTR(4), EINVAL(22), EIO(5), EISDIR(21), etc.
    /// #### Link
    /// Read the docs
    /// [here](https://man7.org/linux/man-pages/man2/read.2.html)
    pub unsafe fn read(fd: c_uint, buf: *mut c_char, count: size_t) -> ssize_t;

    /// write() writes up to count bytes from the buffer starting at buf
    /// to the file referred to by the file descriptor fd.<br>
    /// #### RETURN VALUE
    /// On success, the number of bytes written is returned.  On error, -1
    /// is returned, and errno is set to indicate the error.
    /// #### ERRORS
    /// EAGAIN(35), EBADF(9), EDESTADDRREQ(39), EDQUOT(69), EFAULT(14), EFBIG(27),<br>
    /// EINTR(4), EINVAL(22), EIO(5), ENOSPC(28), EPERM(1), EPIPE(32), etc.
    /// #### Link
    /// Read the docs
    /// [here](https://man7.org/linux/man-pages/man2/write.2.html)
    pub unsafe fn write(fd: c_uint, buf: *const c_char, count: size_t) -> ssize_t;

    /// The open() system call opens the file specified by pathname.  If
    /// the specified file does not exist, it may optionally (if O_CREAT
    /// is specified in flags) be created by open().<br>
    /// #### RETURN VALUE
    /// On success, the number of bytes read is returned (zero indicates
    /// end of file), and the file position is advanced by this number.
    /// #### ERRORS
    /// EAGAIN(35), EBADF(9), EFAULT(14), EINTR(4), EINVAL(22), EIO(5), EISDIR(21), etc.
    /// #### Link
    /// Read the docs
    /// [here](https://man7.org/linux/man-pages/man2/open.2.html)
    pub unsafe fn open(filename: *const c_char, flags: c_int, mode: umode_t) -> c_long;
    

    /// close() closes a file descriptor, so that it no longer refers to
    /// any file and may be reused.<br>
    /// #### RETURN VALUE
    /// close() returns zero on success.  On error, -1 is returned, and
    /// errno is set to indicate the error.<br>
    /// #### ERRORS
    /// EBADF(9), EINTR(4), EIO(5), ENOSPC(28), etc.
    /// #### Link
    /// Read the docs
    /// [here](https://man7.org/linux/man-pages/man2/close.2.html)
    pub unsafe fn close(fd: c_uint) -> c_int;

    pub unsafe fn newstat(filename: *const c_char, statbuf: *mut Stat) -> c_int;
    pub unsafe fn newfstat(fd: c_uint, statbuf: *mut Stat) -> c_int;
    pub unsafe fn newlstat(filename: *const c_char, statbuf: *mut Stat) -> c_int;
    pub unsafe fn poll(ufds: *mut Pollfd, nfds: c_uint, timeout_msecs: c_int) -> c_int;
    pub unsafe fn lseek(fd: c_uint,  offset: off_t, whence: c_uint) -> off_t;
    pub unsafe fn mmap(addr: c_ulong, len: c_ulong, prot: c_ulong, flags: c_ulong, fd: c_ulong, off: c_ulong) -> c_ulong;
    pub unsafe fn mprotect(start: c_ulong, len: size_t, prot: c_ulong) -> c_int;
    pub unsafe fn munmap(addr: c_ulong, len: size_t) -> c_int;
    pub unsafe fn brk(brk: c_ulong) -> c_ulong;


    // pub unsafe fn rt_sigaction	(int sig, const struct sigaction *act, struct sigaction *oact, size_t sigsetsize);
    // pub unsafe fn rt_sigaction(sig: c_int, const struct sigaction *act, struct sigaction *oact, size_t sigsetsize) -> c_int;
    
	// pub unsafe fn rt_sigprocmask				(int how, sigset_t *nset, sigset_t *oset, size_t sigsetsize);
    // pub unsafe fn rt_sigreturn				(void);
    // pub unsafe fn ioctl			(unsigned int fd, unsigned int cmd, unsigned long arg);
    // pub unsafe fn pread64				(unsigned int fd, char *buf, size_t count, loff_t pos);
    // pub unsafe fn pwrite64			(unsigned int fd, const char *buf, size_t count, loff_t pos);
    // pub unsafe fn readv				(unsigned long fd, const struct iovec *vec, unsigned long vlen);
    // pub unsafe fn writev				(unsigned long fd, const struct iovec *vec, unsigned long vlen);
    // pub unsafe fn access				(const char *filename, int mode);
    // pub unsafe fn pipe			(int *fildes);
    // pub unsafe fn select			(int n, fd_set *inp, fd_set *outp, fd_set *exp, struct __kernel_old_timeval *tvp);
    // pub unsafe fn sched_yield				(void);
    // pub unsafe fn mremap				(unsigned long addr, unsigned long old_len, unsigned long new_len, unsigned long flags, unsigned long new_addr);
    // pub unsafe fn msync			(MMU	unsigned long start, size_t len, int flags);
    // pub unsafe fn mincore			(MMU	unsigned long start, size_t len, unsigned char *vec);
    // pub unsafe fn madvise			(ADVISE_SYSCALLS	unsigned long start, size_t len_in, int behavior);
    // pub unsafe fn shmget			(SYSVIPC	key_t key, size_t size, int shmflg);
    // pub unsafe fn shmat			(SYSVIPC	int shmid, char *shmaddr, int shmflg
    // pub unsafe fn shmct			(SYSVIPC	int shmid, int cmd, struct shmid_ds *buf);
    // pub unsafe fn dup				(unsigned int fildes);
    // pub unsafe fn dup2			(unsigned int oldfd, unsigned int newfd);
    // pub unsafe fn pause				(void);
    // pub unsafe fn nanosleep				(struct __kernel_timespec *rqtp, struct __kernel_timespec *rmtp);
    // pub unsafe fn getitimer				(int which, struct __kernel_old_itimerval *value);
    // pub unsafe fn alarm				(unsigned int seconds
    // pub unsafe fn setitimer				(int which, struct __kernel_old_itimerval *value, struct __kernel_old_itimerval *ovalue);
    
    /// getpid() returns the process ID (PID) of the calling process.
    /// (This is often used by routines that generate unique temporary
    /// filenames.)<br>
    /// #### RETURN VALUE
    /// getpid() returns the process ID (PID) of the calling process
    /// #### ERRORS
    /// These functions are always successful.
    /// #### Link
    /// Read the docs
    /// [here](https://man7.org/linux/man-pages/man2/read.2.html)
    pub unsafe fn getpid() -> pid_t;

    // pub unsafe fn sendfile64				(int out_fd, int in_fd, loff_t *offset, size_t count);
    pub unsafe fn socket(family: c_int, _type: c_int, protocol: c_int) -> c_int;
    pub unsafe fn connect(fd: c_int,uservaddr: *mut sockaddr, addrlen: c_int) -> c_int;
    pub unsafe fn accept(fd: c_int, upeer_sockaddr: *mut sockaddr, upeer_addrlen: *mut c_int) -> c_int;
    // pub unsafe fn sendto		(NET	int fd, void *buff, size_t len, unsigned int flags, struct sockaddr *addr, int addr_len);
    // pub unsafe fn recvfrom		(NET	int fd, void *ubuf, size_t size, unsigned int flags, struct sockaddr *addr, int *addr_len);
    // pub unsafe fn sendmsg		(NET	int fd, struct user_msghdr *msg, unsigned int flags);
    // pub unsafe fn recvmsg		(NET	int fd, struct user_msghdr *msg, unsigned int flags);
    // pub unsafe fn shutdown		(NET	int fd, int how);
    pub unsafe fn bind(fd: c_int, umyaddr: *mut sockaddr, addrlen: c_int) -> c_int;
    pub unsafe fn listen(fd: c_int, backlog: c_int) -> c_int;
    // pub unsafe fn getsockname		(NET	int fd, struct sockaddr *usockaddr, int *usockaddr_len);
    // pub unsafe fn getpeername		(NET	int fd, struct sockaddr *usockaddr, int *usockaddr_len);
    // pub unsafe fn socketpair		(NET	int family, int type, int protocol, int *usockvec);
    // pub unsafe fn setsockopt		(NET	int fd, int level, int optname, char *optval, int optlen);
    // pub unsafe fn getsockopt		(NET	int fd, int level, int optname, char *optval, int *optlen);
    // pub unsafe fn clone			(unsigned long clone_flags, unsigned long newsp, int *parent_tidptr, int *child_tidptr, unsigned long tls);
    pub unsafe fn fork() -> pid_t;
    pub unsafe fn vfork() -> pid_t;
    pub unsafe fn execve(filename: *const c_char, argv: *const *const c_char, envp: *const *const c_char) -> c_int;
    pub unsafe fn exit(error_code: c_int);
    // pub unsafe fn wait4			(pid_t upid, int *stat_addr, int options, struct rusage *ru);
    pub unsafe fn kill(pid: pid_t, sig: c_int) -> c_int;
    // pub unsafe fn newuname		(	struct new_utsname *name);
    // pub unsafe fn semget		(SYSVIPC	key_t key, int nsems, int semflg);
    // pub unsafe fn semop		(SYSVIPC	int semid, struct sembuf *tsops, unsigned nsops);
    // pub unsafe fn semctl		(SYSVIPC	int semid, int semnum, int cmd, unsigned long arg);
    // pub unsafe fn shmdt	(SYSVIPC	char *shmaddr);
    // pub unsafe fn msgget		(SYSVIPC	key_t key, int msgflg);
    // pub unsafe fn msgsnd		(SYSVIPC	int msqid, struct msgbuf *msgp, size_t msgsz, int msgflg);
    // pub unsafe fn msgrcv		(SYSVIPC	int msqid, struct msgbuf *msgp, size_t msgsz, long msgtyp, int msgflg);
    // pub unsafe fn msgctl		(SYSVIPC	int msqid, int cmd, struct msqid_ds *buf);
    pub unsafe fn fcntl(fd: c_uint, cmd: c_uint, arg: c_uint) -> c_long;
    pub unsafe fn flock(fd: c_uint, cmd: c_uint) -> c_int;
    pub unsafe fn fsync(fd: c_uint) -> c_int;
    pub unsafe fn fdatasync(fd: c_uint) -> c_int;
    pub unsafe fn truncate(path: *const c_char, length: c_long) -> c_long;
    pub unsafe fn ftruncate(fd: c_uint, length: off_t) -> c_long;
    // pub unsafe fn getdents(unsigned int fd, struct linux_dirent *dirent, unsigned int count);
    pub unsafe fn getcwd(buf: *mut c_char, size: c_ulong) -> c_int;
    pub unsafe fn chdir(filename: *const c_char) -> c_int;
    pub unsafe fn fchdir(fd: c_uint) -> c_int;
    pub unsafe fn rename(oldname: *const c_char, newname: *const c_char) -> c_uint;
    pub unsafe fn mkdir(pathname: *const c_char, mode: umode_t) -> c_int;
    pub unsafe fn rmdir(pathname: *const c_char) -> c_int;
    pub unsafe fn creat(pathname: *const c_char, mode: umode_t) -> c_long;
    pub unsafe fn link(oldname: *const c_char, newname: *const c_char) -> c_int;
    pub unsafe fn unlink(pathname: *const c_char) -> c_int;
    pub unsafe fn symlink(oldname: *const c_char, newname: *const c_char) -> c_int;
    pub unsafe fn readlink(path: *const c_char, buf: *mut c_char, bufsiz: c_int) -> c_int;
    pub unsafe fn chmod(filename: *const c_char,  mode: umode_t) -> c_int;
    pub unsafe fn fchmod(fd: c_int, mode: umode_t) -> c_int;
    pub unsafe fn chown(filename: *const c_char,  user: uid_t,  group: gid_t) -> c_int;
    // pub unsafe fn fchown			(unsigned int fd, uid_t user, gid_t group);
    // pub unsafe fn lchown			(const char *filename, uid_t user, gid_t group);
    pub unsafe fn umask	(mask: c_int) -> c_int;
    // pub unsafe fn gettimeofday			(struct __kernel_old_timeval *tv, struct timezone *tz);
    // pub unsafe fn getrlimit		(unsigned int resource, struct rlimit *rlim);
    // pub unsafe fn getrusage		(int who, struct rusage *ru);
    // pub unsafe fn sysinfo			(struct sysinfo *info);
    // pub unsafe fn times		(struct tms *tbuf);
    // pub unsafe fn ptrace			(long request, long pid, unsigned long addr, unsigned long data);
    pub unsafe fn getuid() -> uid_t;
    pub unsafe fn syslog(_type: c_int, buf: *mut c_char, len: c_int) -> c_int;
    pub unsafe fn getgid() -> uid_t;
    pub unsafe fn setuid(uid: uid_t) -> c_long;
    pub unsafe fn setgid(gid: gid_t) -> c_long;
    pub unsafe fn geteuid() -> uid_t;
    pub unsafe fn getegid() -> uid_t;
    pub unsafe fn setpgid(pid: pid_t, pgid: pid_t) -> c_int;
    pub unsafe fn getppid() -> c_int;
    pub unsafe fn getpgrp() -> c_int;
    pub unsafe fn setsid() -> c_int;
    // pub unsafe fn setreuid		(MULTIUSER	uid_t ruid, uid_t euid);
    // pub unsafe fn setregid		(MULTIUSER	gid_t rgid, gid_t egid);
    // pub unsafe fn getgroups		(MULTIUSER	int gidsetsize, gid_t *grouplist);
    // pub unsafe fn setgroups		(MULTIUSER	int gidsetsize, gid_t *grouplist);
    // pub unsafe fn setresuid		(MULTIUSER	uid_t ruid, uid_t euid, uid_t suid);
    // pub unsafe fn getresuid		(MULTIUSER	uid_t *ruidp, uid_t *euidp, uid_t *suidp);
    // pub unsafe fn setresgid		(MULTIUSER	gid_t rgid, gid_t egid, gid_t sgid);
    // pub unsafe fn getresgid		(MULTIUSER	gid_t *rgidp, gid_t *egidp, gid_t *sgidp);
    // pub unsafe fn getpgid			(pid_t pid);
    // pub unsafe fn setfsuid		(MULTIUSER	uid_t uid);
    // pub unsafe fn setfsgid		(MULTIUSER	gid_t gid);
    // pub unsafe fn getsid			(pid_t pid);
    // pub unsafe fn capget		(MULTIUSER	cap_user_header_t header, cap_user_data_t dataptr);
    // pub unsafe fn capset	(MULTIUSER	cap_user_header_t header, const cap_user_data_t data);
    // pub unsafe fn rt_sigpending			(sigset_t *uset, size_t sigsetsize);
    // pub unsafe fn rt_sigtimedwait			(const sigset_t *uthese, siginfo_t *uinfo, const struct __kernel_timespec *uts, size_t sigsetsize);

    // pub unsafe fn rt_sigsuspend			(sigset_t *unewset, size_t sigsetsize);
    // pub unsafe fn rt_sigqueueinfo			(pid_t pid, int sig, siginfo_t *uinfo);
    // pub unsafe fn sigaltstack			(const stack_t *uss, stack_t *uoss);
    // pub unsafe fn utime		(char *filename, struct utimbuf *times);
    // pub unsafe fn mknod			(const char *filename, umode_t mode, unsigned dev);
    // pub unsafe fn personality			(unsigned int personality);
    // pub unsafe fn ustat		(unsigned dev, struct ustat *ubuf);
    // pub unsafe fn statfs			(const char *pathname, struct statfs *buf);
    // pub unsafe fn fstatfs		(unsigned int fd, struct statfs *buf);
    // pub unsafe fn sysfs		(SYSFS_SYSCALL	int option, unsigned long arg1, unsigned long arg2);
    // pub unsafe fn getpriority			(int which, int who);
    // pub unsafe fn setpriority		(int which, int who, int niceval);
    // pub unsafe fn sched_setparam		(pid_t pid, struct sched_param *param);
    // pub unsafe fn sched_getparam			(pid_t pid, struct sched_param *param);
    // pub unsafe fn sched_setscheduler			(pid_t pid, int policy, struct sched_param *param);
    // pub unsafe fn sched_getscheduler			(pid_t pid);
    // pub unsafe fn sched_get_priority_max			(int policy);
    // pub unsafe fn sched_get_priority_min			(int policy);
    // pub unsafe fn sched_rr_get_interval	(		pid_t pid, struct __kernel_timespec *interval);
    // pub unsafe fn mlock	(	MMU	unsigned long start, size_t len);
    // pub unsafe fn munlock	(	MMU	unsigned long start, size_t len);
    // pub unsafe fn mlockall	(	MMU	int flags);
    // pub unsafe fn munlockall	(	MMU	void);
    // pub unsafe fn vhangup	(		void);
    // pub unsafe fn modify_ldt	(	MODIFY_LDT_SYSCALL	int func, void *ptr, unsigned long bytecount);
    // pub unsafe fn pivot_root	(	const char *new_root, const char *put_old);
    // pub unsafe fn prctl	(		int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);
    // pub unsafe fn arch_prctl	(		int option, unsigned long arg2);
    // pub unsafe fn adjtimex	(		struct __kernel_timex *txc_p);
    // pub unsafe fn setrlimit	(		unsigned int resource, struct rlimit *rlim);
    // pub unsafe fn chroot	(		const char *filename);
    // pub unsafe fn sync	(		void);
    // pub unsafe fn acct	(	BSD_PROCESS_ACCT	const char *name);
    // pub unsafe fn settimeofday	(		struct __kernel_old_timeval *tv, struct timezone *tz);
    pub unsafe fn mount(dev_name: *mut c_char, dir_name: *mut c_char, _type: *mut c_char, flags: c_ulong, data: *mut c_void) -> c_int;
    pub unsafe fn umount(name: *mut c_char, flags: c_int) -> c_int;
    pub unsafe fn swapon(specialfile: *const c_char, swap_flags: c_int) -> c_int;
    pub unsafe fn swapoff(specialfile: *const c_char);
    // pub unsafe fn reboot	(		int magic1, int magic2, unsigned int cmd, void *arg);
    // pub unsafe fn sethostname	(char *name, int len);
    // pub unsafe fn setdomainname(		char *name, int len);
    // pub unsafe fn statmount	(		const struct mnt_id_req *req, struct statmount *buf, size_t bufsize, unsigned int flags);
	// pub unsafe fn listmount	(		const struct mnt_id_req *req, u64 *mnt_ids, size_t nr_mnt_ids, unsigned int flags);
	// pub unsafe fn lsm_get_self_attr	(	SECURITY	unsigned int attr, struct lsm_ctx *ctx, u32 *size, u32 flags);
	// pub unsafe fn lsm_set_self_attr	(	SECURITY	unsigned int attr, struct lsm_ctx *ctx, u32 size, u32 flags);
	// pub unsafe fn lsm_list_modules	(	SECURITY	u64 *ids, u32 *size, u32 flags);
	// pub unsafe fn mseal	(		unsigned long start, size_t len, unsigned long flags);
	// pub unsafe fn setxattrat	(		int dfd, const char *pathname, unsigned int at_flags, const char *name, const struct xattr_args *uargs, size_t usize);
	// pub unsafe fn getxattrat	(		int dfd, const char *pathname, unsigned int at_flags, const char *name, struct xattr_args *uargs, size_t usize);
	// pub unsafe fn listxattrat	(		int dfd, const char *pathname, unsigned int at_flags, char *list, size_t size);
	// pub unsafe fn removexattrat	(		int dfd, const char *pathname, unsigned int at_flags, const char *name);
    // pub unsafe fn iopl	(	X86_IOPL_IOPERM	unsigned int level);
	// pub unsafe fn ioperm	(	X86_IOPL_IOPERM	unsigned long from, unsigned long num, int turn_on);
	// pub unsafe fn init_module	(	MODULES	void *umod, unsigned long len, const char *uargs);
	// pub unsafe fn delete_module	(	MODULE_UNLOAD	const char *name_user, unsigned int flags);
	// pub unsafe fn quotactl	(	QUOTACTL	unsigned int cmd, const char *special, qid_t id, void *addr);
	// pub unsafe fn gettid	(		void);
	// pub unsafe fn readahead	(		int fd, loff_t offset, size_t count);
	// pub unsafe fn setxattr	(		const char *pathname, const char *name, const void *value, size_t size, int flags);
	// pub unsafe fn lsetxattr	(		const char *pathname, const char *name, const void *value, size_t size, int flags);
	// pub unsafe fn fsetxattr	(		int fd, const char *name, const void *value, size_t size, int flags);
    // pub unsafe fn getxattr	(		const char *pathname, const char *name, void *value, size_t size);
	// pub unsafe fn lgetxattr	(		const char *pathname, const char *name, void *value, size_t size);
	// pub unsafe fn fgetxattr	(		int fd, const char *name, void *value, size_t size);
	// pub unsafe fn listxattr	(	const char *pathname, char *list, size_t size);
	// pub unsafe fn llistxattr	(		const char *pathname, char *list, size_t size);
	// pub unsafe fn flistxattr	(		int fd, char *list, size_t size);
	// pub unsafe fn removexattr	(		const char *pathname, const char *name);
	// pub unsafe fn lremovexattr	(	const char *pathname, const char *name);
	// pub unsafe fn fremovexattr	(		int fd, const char *name);
    // pub unsafe fn tkill	(		pid_t pid, int sig);
	// pub unsafe fn time	(		__kernel_old_time_t *tloc);
	// pub unsafe fn futex	(	FUTEX	u32 *uaddr, int op, u32 val, const struct __kernel_timespec *utime, u32 *uaddr2, u32 val3);
	// pub unsafe fn sched_setaffinity(		pid_t pid, unsigned int len, unsigned long *user_mask_ptr);
	// pub unsafe fn sched_getaffinity	(		pid_t pid, unsigned int len, unsigned long *user_mask_ptr);
	// pub unsafe fn io_setup	(	AIO	unsigned nr_events, aio_context_t *ctxp);
	// pub unsafe fn io_destroy	(	AIO	aio_context_t ctx);
	// pub unsafe fn io_getevents	(	AIO	aio_context_t ctx_id, long min_nr, long nr, struct io_event *events, struct __kernel_timespec *timeout);
	// pub unsafe fn io_submit	(	AIO	aio_context_t ctx_id, long nr, struct iocb **iocbpp);
	// pub unsafe fn io_cancel	(	AIO	aio_context_t ctx_id, struct iocb *iocb, struct io_event *result);
	// pub unsafe fn epoll_create	(	EPOLL	int size
	// pub unsafe fn remap_file_pages	(	MMU	unsigned long start, unsigned long size, unsigned long prot, unsigned long pgoff, unsigned long flags);
	// pub unsafe fn getdents64	(		unsigned int fd, struct linux_dirent64 *dirent, unsigned int count);
	// pub unsafe fn set_tid_address	(		int *tidptr);
	// pub unsafe fn restart_syscall	(		void);
	// pub unsafe fn semtimedop	(	SYSVIPC	int semid, struct sembuf *tsops, unsigned int nsops, const struct __kernel_timespec *timeout);
	// pub unsafe fn fadvise64	(	ADVISE_SYSCALLS	int fd, loff_t offset, size_t len, int advice);
    // pub unsafe fn timer_create	(	const clockid_t which_clock, struct sigevent *timer_event_spec, timer_t *created_timer_id);
	// pub unsafe fn timer_settime	(	timer_t timer_id, int flags, const struct __kernel_itimerspec *new_setting, struct __kernel_itimerspec *old_setting);
	// pub unsafe fn timer_gettime	(	timer_t timer_id, struct __kernel_itimerspec *setting);
	// pub unsafe fn timer_getoverrun	(	timer_t timer_id);
	// pub unsafe fn timer_delete	(	timer_t timer_id);

    // 	pub unsafe fn clock_settime	(		const clockid_t which_clock, const struct __kernel_timespec *tp);
    // 	pub unsafe fn clock_gettime(		const clockid_t which_clock, struct __kernel_timespec *tp);
    // 	pub unsafe fn clock_getres	(	const clockid_t which_clock, struct __kernel_timespec *tp);
    // 	pub unsafe fn clock_nanosleep	(		const clockid_t which_clock, int flags, const struct __kernel_timespec *rqtp, struct __kernel_timespec *rmtp);
    // pub unsafe fn exit_group	(		int error_code);
	// pub unsafe fn epoll_wait	(	EPOLL	int epfd, struct epoll_event *events, int maxevents, int timeout);
	// pub unsafe fn epoll_ctl	(	EPOLL	int epfd, int op, int fd, struct epoll_event *event);
	// pub unsafe fn tgkill	(		pid_t tgid, pid_t pid, int sig);
	// pub unsafe fn utimes	(		char *filename, struct __kernel_old_timeval *utimes);
	// pub unsafe fn mbind	(	NUMA	unsigned long start, unsigned long len, unsigned long mode, const unsigned long *nmask, unsigned long maxnode, unsigned int flags);
	// pub unsafe fn set_mempolicy	(	NUMA	int mode, const unsigned long *nmask, unsigned long maxnode);
	// pub unsafe fn get_mempolicy(	NUMA	int *policy, unsigned long *nmask, unsigned long maxnode, unsigned long addr, unsigned long flags);
	// pub unsafe fn mq_open	(	POSIX_MQUEUE	const char *u_name, int oflag, umode_t mode, struct mq_attr *u_attr);
	// pub unsafe fn mq_unlink	(	POSIX_MQUEUE	const char *u_name);
    //  pub unsafe fn mq_timedsend	 (	POSIX_MQUEUE	mqd_t mqdes, const char *u_msg_ptr, size_t msg_len, unsigned int msg_prio, const struct __kernel_timespec *u_abs_timeout);
    // 	pub unsafe fn mq_timedreceive	 (	POSIX_MQUEUE	mqd_t mqdes, char *u_msg_ptr, size_t msg_len, unsigned int *u_msg_prio, const struct __kernel_timespec *u_abs_timeout);
    // 	pub unsafe fn mq_notify (	POSIX_MQUEUE	mqd_t mqdes, const struct sigevent *u_notification);
    // 	pub unsafe fn mq_getsetattr	 (	POSIX_MQUEUE	mqd_t mqdes, const struct mq_attr *u_mqstat, struct mq_attr *u_omqstat);
    // 	pub unsafe fn kexec_load	 (	KEXEC	unsigned long entry, unsigned long nr_segments, struct kexec_segment *segments, unsigned long flags);
    // 	pub unsafe fn waitid	 (		int which, pid_t upid, struct siginfo *infop, int options, struct rusage *ru);
    // 	pub unsafe fn add_key	 (	KEYS	const char *_type, const char *_description, const void *_payload, size_t plen, key_serial_t ringid);
    // 	pub unsafe fn request_key	 (	KEYS	const char *_type, const char *_description, const char *_callout_info, key_serial_t destringid);
    // 	pub unsafe fn keyctl	 (	KEYS	int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);
    // 	pub unsafe fn ioprio_set	 (	BLOCK	int which, int who, int ioprio);
    // 	pub unsafe fn ioprio_get	 (	BLOCK	int which, int who);
    // 	pub unsafe fn inotify_init	 (	INOTIFY_USER	void);
    // 	pub unsafe fn inotify_add_watch	 (	INOTIFY_USER	int fd, const char *pathname, u32 mask);
    // 	pub unsafe fn inotify_rm_watch	 (	INOTIFY_USER	int fd, __s32 wd);
    
	// pub unsafe fn migrate_pages	(	MIGRATION	pid_t pid, unsigned long maxnode, const unsigned long *old_nodes, const unsigned long *new_nodes);
	// pub unsafe fn openat	(		int dfd, const char *filename, int flags, umode_t mode);
	// pub unsafe fn mkdirat	(		int dfd, const char *pathname, umode_t mode);
	// pub unsafe fn mknodat	(		int dfd, const char *filename, umode_t mode, unsigned int dev);
	// pub unsafe fn fchownat	(		int dfd, const char *filename, uid_t user, gid_t group, int flag);
	// pub unsafe fn futimesat	(		int dfd, const char *filename, struct __kernel_old_timeval *utimes);
	// pub unsafe fn newfstatat	(		int dfd, const char *filename, struct stat *statbuf, int flag);
	// pub unsafe fn unlinkat	(		int dfd, const char *pathname, int flag);
	// pub unsafe fn renameat	(		int olddfd, const char *oldname, int newdfd, const char *newname);
	// pub unsafe fn linkat	(		int olddfd, const char *oldname, int newdfd, const char *newname, int flags);
    // pub unsafe fn symlinkat	(		const char *oldname, int newdfd, const char *newname);
	// pub unsafe fn readlinkat	(		int dfd, const char *pathname, char *buf, int bufsiz);
	// pub unsafe fn fchmodat	(		int dfd, const char *filename, umode_t mode);
	// pub unsafe fn faccessat	(		int dfd, const char *filename, int mode);
	// pub unsafe fn pselect6	(		int n, fd_set *inp, fd_set *outp, fd_set *exp, struct __kernel_timespec *tsp, void *sig);
	// pub unsafe fn ppoll	(		struct pollfd *ufds, unsigned int nfds, struct __kernel_timespec *tsp, const sigset_t *sigmask, size_t sigsetsize);
	// pub unsafe fn unshare	(		unsigned long unshare_flags);
	// pub unsafe fn set_robust_list	(	FUTEX	struct robust_list_head *head, size_t len);
	// pub unsafe fn get_robust_list	(	FUTEX	int pid, struct robust_list_head **head_ptr, size_t *len_ptr);
    // pub unsafe fn splice	(		int fd_in, loff_t *off_in, int fd_out, loff_t *off_out, size_t len, unsigned int flags);
	// pub unsafe fn tee	(		int fdin, int fdout, size_t len, unsigned int flags);
	// pub unsafe fn sync_file_range	(		int fd, loff_t offset, loff_t nbytes, unsigned int flags);
	// pub unsafe fn vmsplice	(		int fd, const struct iovec *uiov, unsigned long nr_segs, unsigned int flags);
	// pub unsafe fn move_pages	(	MIGRATION	pid_t pid, unsigned long nr_pages, const void **pages, const int *nodes, int *status, int flags);
	// pub unsafe fn utimensat	(		int dfd, const char *filename, struct __kernel_timespec *utimes, int flags);
	// pub unsafe fn epoll_pwait	(	EPOLL	int epfd, struct epoll_event *events, int maxevents, int timeout, const sigset_t *sigmask, size_t sigsetsize);
	// pub unsafe fn signalfd	(	SIGNALFD	int ufd, sigset_t *user_mask, size_t sizemask);
	// pub unsafe fn timerfd_create	(		int clockid, int flags);
	// pub unsafe fn eventfd	(		unsigned int count);
	// pub unsafe fn fallocate	(		int fd, int mode, loff_t offset, loff_t len);
    // pub unsafe fn timerfd_settime	 (		int ufd, int flags, const struct __kernel_itimerspec *utmr, struct __kernel_itimerspec *otmr);
	// pub unsafe fn timerfd_gettime	 (		int ufd, struct __kernel_itimerspec *otmr);
	// pub unsafe fn accept4	 (	NET	int fd, struct sockaddr *upeer_sockaddr, int *upeer_addrlen, int flags);
	// pub unsafe fn signalfd4 (	SIGNALFD	int ufd, sigset_t *user_mask, size_t sizemask, int flags);
	// pub unsafe fn eventfd2	 (		unsigned int count, int flags);
	// pub unsafe fn epoll_create1	 (	EPOLL	int flags);
	// pub unsafe fn dup3	 (		unsigned int oldfd, unsigned int newfd, int flags);
	// pub unsafe fn pipe2	 (		int *fildes, int flags);
	// pub unsafe fn inotify_init1	 (	INOTIFY_USER	int flags);
    // pub unsafe fn preadv	(		unsigned long fd, const struct iovec *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h);
	// pub unsafe fn pwritev	(		unsigned long fd, const struct iovec *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h);
	// pub unsafe fn rt_tgsigqueueinfo(		pid_t tgid, pid_t pid, int sig, siginfo_t *uinfo);
	// pub unsafe fn perf_event_open	(	PERF_EVENTS	struct perf_event_attr *attr_uptr, pid_t pid, int cpu, int group_fd, unsigned long flags);
	// pub unsafe fn recvmmsg	(	NET	int fd, struct mmsghdr *mmsg, unsigned int vlen, unsigned int flags, struct __kernel_timespec *timeout);
    // pub unsafe fn fanotify_init	(	FANOTIFY	unsigned int flags, unsigned int event_f_flags);
	// pub unsafe fn fanotify_mark	(	FANOTIFY	int fanotify_fd, unsigned int flags, __u64 mask, int dfd, const char *pathname);
	// pub unsafe fn prlimit64	(		pid_t pid, unsigned int resource, const struct rlimit64 *new_rlim, struct rlimit64 *old_rlim);
	// pub unsafe fn name_to_handle_at	(	FHANDLE	int dfd, const char *name, struct file_handle *handle, void *mnt_id, int flag);
	// pub unsafe fn open_by_handle_at	(	FHANDLE	int mountdirfd, struct file_handle *handle, int flags);
	// pub unsafe fn clock_adjtime	(		const clockid_t which_clock, struct __kernel_timex *utx);
	// pub unsafe fn syncfs	(		int fd);
    // pub unsafe fn sendmmsg	(	NET	int fd, struct mmsghdr *mmsg, unsigned int vlen, unsigned int flags);
	// pub unsafe fn setns	(		int fd, int flags);
	// pub unsafe fn getcpu	(		unsigned *cpup, unsigned *nodep, struct getcpu_cache *unused);
	// pub unsafe fn process_vm_readv	(	CROSS_MEMORY_ATTACH	pid_t pid, const struct iovec *lvec, unsigned long liovcnt, const struct iovec *rvec, unsigned long riovcnt, unsigned long flags);
	// pub unsafe fn process_vm_writev	(	CROSS_MEMORY_ATTACH	pid_t pid, const struct iovec *lvec, unsigned long liovcnt, const struct iovec *rvec, unsigned long riovcnt, unsigned long flags);
	// pub unsafe fn kcmp	(	KCMP	pid_t pid1, pid_t pid2, int type, unsigned long idx1, unsigned long idx2);
	// pub unsafe fn finit_module	(	MODULES	int fd, const char *uargs, int flags);
    // pub unsafe fn sched_setattr (		pid_t pid, struct sched_attr *uattr, unsigned int flags);
	// pub unsafe fn sched_getattr	 (		pid_t pid, struct sched_attr *uattr, unsigned int usize, unsigned int flags);
	// pub unsafe fn renameat2 (	int olddfd, const char *oldname, int newdfd, const char *newname, unsigned int flags);
	// pub unsafe fn seccomp	 (	SECCOMP	unsigned int op, unsigned int flags, void *uargs);
	// pub unsafe fn getrandom	 (		char *ubuf, size_t len, unsigned int flags);
	// pub unsafe fn memfd_create	 (	MEMFD_CREATE	const char *uname, unsigned int flags);
	// pub unsafe fn kexec_file_load	 (	KEXEC_FILE	int kernel_fd, int initrd_fd, unsigned long cmdline_len, const char *cmdline_ptr, unsigned long flags);
    // pub unsafe fn bpf	(	BPF_SYSCALL	int cmd, union bpf_attr *uattr, unsigned int size);
	// pub unsafe fn execveat	(		int fd, const char *filename, const char *const *argv, const char *const *envp, int flags);
	// pub unsafe fn userfaultfd	(	USERFAULTFD	int flags);
	// pub unsafe fn membarrier	(	MEMBARRIER	int cmd, unsigned int flags, int cpu_id);
	// pub unsafe fn mlock2	(	MMU	unsigned long start, size_t len, int flags);
	// pub unsafe fn copy_file_range	(		int fd_in, loff_t *off_in, int fd_out, loff_t *off_out, size_t len, unsigned int flags);
    // pub unsafe fn preadv2	(		unsigned long fd, const struct iovec *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h, rwf_t flags);
	// pub unsafe fn pwritev2	(		unsigned long fd, const struct iovec *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h, rwf_t flags);
	// pub unsafe fn pkey_mprotect	(	X86_INTEL_MEMORY_PROTECTION_KEYS	unsigned long start, size_t len, unsigned long prot, int pkey);
	// pub unsafe fn pkey_alloc	(	X86_INTEL_MEMORY_PROTECTION_KEYS	unsigned long flags, unsigned long init_val);
	// pub unsafe fn pkey_free	(	X86_INTEL_MEMORY_PROTECTION_KEYS	int pkey);
	// pub unsafe fn statx	(		int dfd, const char *filename, unsigned flags, unsigned int mask, struct statx *buffer);
	// pub unsafe fn io_pgetevents	(	AIO	aio_context_t ctx_id, long min_nr, long nr, struct io_event *events, struct __kernel_timespec *timeout, const struct __aio_sigset *usig);
	// pub unsafe fn rseq	(	RSEQ	struct rseq *rseq, u32 rseq_len, int flags, u32 sig);
	// pub unsafe fn uretprobe	(		void);
	// pub unsafe fn pidfd_send_signal	(		int pidfd, int sig, siginfo_t *info, unsigned int flags);
    // pub unsafe fn io_uring_setup	(	IO_URING	u32 entries, struct io_uring_params *params);
	// pub unsafe fn io_uring_enter	(	IO_URING	unsigned int fd, u32 to_submit, u32 min_complete, u32 flags, const void *argp, size_t argsz);
	// pub unsafe fn io_uring_register	(	IO_URING	unsigned int fd, unsigned int opcode, void *arg, unsigned int nr_args);
	// pub unsafe fn open_tree	(		int dfd, const char *filename, unsigned flags);
	// pub unsafe fn move_mount	(		int from_dfd, const char *from_pathname, int to_dfd, const char *to_pathname, unsigned int flags);
	// pub unsafe fn fsopen	(	const char *_fs_name, unsigned int flags);
	// pub unsafe fn fsconfig(		int fd, unsigned int cmd, const char *_key, const void *_value, int aux);
	// pub unsafe fn fsmount	(	int fs_fd, unsigned int flags, unsigned int attr_flags);
	// pub unsafe fn fspick	(		int dfd, const char *path, unsigned int flags);
	// pub unsafe fn pidfd_open	(		pid_t pid, unsigned int flags);
	// pub unsafe fn clone3	(		struct clone_args *uargs, size_t size);
	// pub unsafe fn close_range	(		unsigned int fd, unsigned int max_fd, unsigned int flags);
	// pub unsafe fn openat2	(		int dfd, const char *filename, struct open_how *how, size_t usize);
    // pub unsafe fn pidfd_getfd	(		int pidfd, int fd, unsigned int flags);
	// pub unsafe fn faccessat2	(		int dfd, const char *filename, int mode, int flags);
	// pub unsafe fn process_madvise	(	ADVISE_SYSCALLS	int pidfd, const struct iovec *vec, size_t vlen, int behavior, unsigned int flags);
	// pub unsafe fn epoll_pwait2	(	EPOLL	int epfd, struct epoll_event *events, int maxevents, const struct __kernel_timespec *timeout, const sigset_t *sigmask, size_t sigsetsize);
	// pub unsafe fn mount_setattr	(		int dfd, const char *path, unsigned int flags, struct mount_attr *uattr, size_t usize);
	// pub unsafe fn quotactl_fd	(	QUOTACTL	unsigned int fd, unsigned int cmd, qid_t id, void *addr);
	// pub unsafe fn landlock_create_ruleset	(	SECURITY_LANDLOCK	const struct landlock_ruleset_attr *const attr, const size_t size, const __u32 flags);
	// pub unsafe fn landlock_add_rule	(	SECURITY_LANDLOCK	const int ruleset_fd, const enum landlock_rule_type rule_type, const void *const rule_attr, const __u32 flags);
	// pub unsafe fn landlock_restrict_self	(	SECURITY_LANDLOCK	const int ruleset_fd, const __u32 flags);
	// pub unsafe fn memfd_secret	(	SECRETMEM	unsigned int flags);
	// pub unsafe fn process_mrelease	(	MMU	int pidfd, unsigned int flags);
	// pub unsafe fn futex_waitv	(	FUTEX	struct futex_waitv *waiters, unsigned int nr_futexes, unsigned int flags, struct __kernel_timespec *timeout, clockid_t clockid);
	// pub unsafe fn set_mempolicy_home_node	(	NUMA	unsigned long start, unsigned long len, unsigned long home_node, unsigned long flags);
	// pub unsafe fn cachestat	(	CACHESTAT_SYSCALL	unsigned int fd, struct cachestat_range *cstat_range, struct cachestat *cstat, unsigned int flags);
	// pub unsafe fn fchmodat2	(		int dfd, const char *filename, umode_t mode, unsigned int flags);
	// pub unsafe fn map_shadow_stack	(	X86_USER_SHADOW_STACK	unsigned long addr, unsigned long size, unsigned int flags);
	// pub unsafe fn futex_wake	(	FUTEX	void *uaddr, unsigned long mask, int nr, unsigned int flags);
	// pub unsafe fn futex_wait	(	FUTEX	void *uaddr, unsigned long val, unsigned long mask, unsigned int flags, struct __kernel_timespec *timeout, clockid_t clockid);
	// pub unsafe fn futex_requeue	(	FUTEX	struct futex_waitv *waiters, unsigned int flags, int nr_wake, int nr_requeue);
}






	
