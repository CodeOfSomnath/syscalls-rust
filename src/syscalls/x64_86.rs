use std::ffi::*;
use crate::types::*;

// Rules
// size_t -> c_uint
// unsigned int -> c_uint
// char * -> *mut c_char
// const char * -> *const c_char


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


unsafe extern "system" {
    pub unsafe fn read(fd: c_uint, buf: *mut c_char, count: size_t) -> ssize_t;
    pub unsafe fn write(fd: c_uint, buf: *const c_char, count: size_t) -> ssize_t;
    pub unsafe fn open(filename: *const c_char, flags: c_int, mode: umode_t) -> c_long;
    pub unsafe fn close(fd: c_uint) -> c_int;

    // TODO: change the types to define type
    pub unsafe fn newstat(filename: *const c_char, statbuf: *mut Stat) -> c_int;
    pub unsafe fn newfstat(fd: c_uint, statbuf: *mut Stat) -> c_int;
    pub unsafe fn newlstat(filename: *const c_char, statbuf: *mut Stat) -> c_int;
    pub unsafe fn poll(ufds: *mut Pollfd, nfds: c_uint, timeout_msecs: c_int) -> c_int;
    pub unsafe fn lseek(fd: c_uint,  offset: off_t, whence: c_uint) -> c_long;
    pub unsafe fn mmap(addr: c_ulong, len: c_ulong, prot: c_ulong, flags: c_ulong, fd: c_ulong, off: c_ulong) -> c_ulong;
    pub unsafe fn mprotect(start: c_ulong, len: c_uint, prot: c_ulong) -> c_int;
    // pub unsafe fn munmap(unsigned long addr, size_t len);
    pub unsafe fn munmap(addr: c_ulong, len: c_ulong) -> c_int;
    // pub unsafe fn brk				(unsigned long brk);
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
    
    // pub unsafe fn getpid				(void);
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
    // pub unsafe fn fcntl		(unsigned int fd, unsigned int cmd, unsigned long arg);
    // pub unsafe fn flock			(unsigned int fd, unsigned int cmd);
    // pub unsafe fn fsync			(unsigned int fd);
    // pub unsafe fn fdatasync			(unsigned int fd);
    // pub unsafe fn truncate			(const char *path, long length);
    // pub unsafe fn ftruncate			(unsigned int fd, off_t length);
    // pub unsafe fn getdents			(unsigned int fd, struct linux_dirent *dirent, unsigned int count);
    pub unsafe fn getcwd(buf: *mut c_char, size: c_ulong) -> c_int;
    pub unsafe fn chdir(filename: *const c_char) -> c_int;
    pub unsafe fn fchdir(fd: c_uint) -> c_int;
    pub unsafe fn rename(oldname: *const c_char, newname: *const c_char) -> c_uint;
    pub unsafe fn mkdir(pathname: *const c_char, mode: umode_t) -> c_int;
    pub unsafe fn rmdir(pathname: *const c_char) -> c_int;
    pub unsafe fn creat(pathname: *const c_char, mode: umode_t) -> c_long;
    // pub unsafe fn link			(const char *oldname, const char *newname);
    // pub unsafe fn unlink		(const char *pathname);
    // pub unsafe fn symlink			(const char *oldname, const char *newname);
    // pub unsafe fn readlink			(const char *path, char *buf, int bufsiz);
    pub unsafe fn chmod(filename: *const c_char,  mode: umode_t) -> c_int;
    // pub unsafe fn fchmod			(unsigned int fd, umode_t mode);
    pub unsafe fn chown(filename: *const c_char,  user: uid_t,  group: gid_t) -> c_int;
    // pub unsafe fn fchown			(unsigned int fd, uid_t user, gid_t group);
    // pub unsafe fn lchown			(const char *filename, uid_t user, gid_t group);
    // pub unsafe fn umask		(int mask);
    // pub unsafe fn gettimeofday			(struct __kernel_old_timeval *tv, struct timezone *tz);
    // pub unsafe fn getrlimit		(unsigned int resource, struct rlimit *rlim);
    // pub unsafe fn getrusage		(int who, struct rusage *ru);
    // pub unsafe fn sysinfo			(struct sysinfo *info);
    // pub unsafe fn times		(struct tms *tbuf);
    // pub unsafe fn ptrace			(long request, long pid, unsigned long addr, unsigned long data);
    // pub unsafe fn getuid			(void);
    // pub unsafe fn syslog			(int type, char *buf, int len);
    // pub unsafe fn getgid			(void);
    // pub unsafe fn setuid		(MULTIUSER	uid_t uid);
    // pub unsafe fn setgid	(MULTIUSER	gid_t gid);
    // pub unsafe fn geteuid			(void);
    // pub unsafe fn getegid			(void);
    // pub unsafe fn setpgid			(pid_t pid, pid_t pgid);
    // pub unsafe fn getppid			(void);
    // pub unsafe fn getpgrp			(void);
    // pub unsafe fn setsid			(void);
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
    // pub unsafe fn mount	(		char *dev_name, char *dir_name, char *type, unsigned long flags, void *data);
    // pub unsafe fn umount	(		char *name, int flags);
    // pub unsafe fn swapon	(	SWAP	const char *specialfile, int swap_flags);
    // pub unsafe fn swapoff	(	SWAP	const char *specialfile);
    // pub unsafe fn reboot	(		int magic1, int magic2, unsigned int cmd, void *arg);
    // pub unsafe fn sethostname	(		char *name, int len);
    // pub unsafe fn setdomainname(		char *name, int len);
}

// 	pub unsafe fn iopl	__x64_sys_iopl	arch/x86/kernel/ioport.c:173	X86_IOPL_IOPERM	unsigned int level
// 	pub unsafe fn ioperm	__x64_sys_ioperm	arch/x86/kernel/ioport.c:152	X86_IOPL_IOPERM	unsigned long from, unsigned long num, int turn_on
// 	pub unsafe fn init_module	__x64_sys_init_module	kernel/module/main.c:3433	MODULES	void *umod, unsigned long len, const char *uargs
// 	pub unsafe fn delete_module	__x64_sys_delete_module	kernel/module/main.c:732	MODULE_UNLOAD	const char *name_user, unsigned int flags
// 	pub unsafe fn quotactl	__x64_sys_quotactl	fs/quota/quota.c:917	QUOTACTL	unsigned int cmd, const char *special, qid_t id, void *addr
// 	pub unsafe fn gettid	__x64_sys_gettid	kernel/sys.c:973		void
// 	pub unsafe fn readahead	__x64_sys_readahead	mm/readahead.c:702		int fd, loff_t offset, size_t count
// 	pub unsafe fn setxattr	__x64_sys_setxattr	fs/xattr.c:743		const char *pathname, const char *name, const void *value, size_t size, int flags
// 	pub unsafe fn lsetxattr	__x64_sys_lsetxattr	fs/xattr.c:750		const char *pathname, const char *name, const void *value, size_t size, int flags
// 	pub unsafe fn fsetxattr	__x64_sys_fsetxattr	fs/xattr.c:758		int fd, const char *name, const void *value, size_t size, int flags
// 	pub unsafe fn getxattr	__x64_sys_getxattr	fs/xattr.c:888		const char *pathname, const char *name, void *value, size_t size
// 	pub unsafe fn lgetxattr	__x64_sys_lgetxattr	fs/xattr.c:894		const char *pathname, const char *name, void *value, size_t size
// 	pub unsafe fn fgetxattr	__x64_sys_fgetxattr	fs/xattr.c:901		int fd, const char *name, void *value, size_t size
// 	pub unsafe fn listxattr	__x64_sys_listxattr	fs/xattr.c:998		const char *pathname, char *list, size_t size
// 	pub unsafe fn llistxattr	__x64_sys_llistxattr	fs/xattr.c:1004		const char *pathname, char *list, size_t size
// 	pub unsafe fn flistxattr	__x64_sys_flistxattr	fs/xattr.c:1010		int fd, char *list, size_t size
// 	pub unsafe fn removexattr	__x64_sys_removexattr	fs/xattr.c:1097		const char *pathname, const char *name
// 	pub unsafe fn lremovexattr	__x64_sys_lremovexattr	fs/xattr.c:1103		const char *pathname, const char *name
// 	pub unsafe fn fremovexattr	__x64_sys_fremovexattr	fs/xattr.c:1109		int fd, const char *name
// 	pub unsafe fn tkill	__x64_sys_tkill	kernel/signal.c:4160		pid_t pid, int sig
// 	pub unsafe fn time	__x64_sys_time	kernel/time/time.c:62		__kernel_old_time_t *tloc
// 	pub unsafe fn futex	__x64_sys_futex	kernel/futex/syscalls.c:160	FUTEX	u32 *uaddr, int op, u32 val, const struct __kernel_timespec *utime, u32 *uaddr2, u32 val3
// 	pub unsafe fn sched_setaffinity	__x64_sys_sched_setaffinity	kernel/sched/syscalls.c:1282		pid_t pid, unsigned int len, unsigned long *user_mask_ptr
// 	pub unsafe fn sched_getaffinity	__x64_sys_sched_getaffinity	kernel/sched/syscalls.c:1327		pid_t pid, unsigned int len, unsigned long *user_mask_ptr
// 	pub unsafe fn io_setup	__x64_sys_io_setup	fs/aio.c:1382	AIO	unsigned nr_events, aio_context_t *ctxp
// 	pub unsafe fn io_destroy	__x64_sys_io_destroy	fs/aio.c:1451	AIO	aio_context_t ctx
// 	pub unsafe fn io_getevents	__x64_sys_io_getevents	fs/aio.c:2250	AIO	aio_context_t ctx_id, long min_nr, long nr, struct io_event *events, struct __kernel_timespec *timeout
// 	pub unsafe fn io_submit	__x64_sys_io_submit	fs/aio.c:2081	AIO	aio_context_t ctx_id, long nr, struct iocb **iocbpp
// 	pub unsafe fn io_cancel	__x64_sys_io_cancel	fs/aio.c:2175	AIO	aio_context_t ctx_id, struct iocb *iocb, struct io_event *result
// 	pub unsafe fn epoll_create	__x64_sys_epoll_create	fs/eventpoll.c:2256	EPOLL	int size
// 	pub unsafe fn remap_file_pages	__x64_sys_remap_file_pages	mm/mmap.c:1396	MMU	unsigned long start, unsigned long size, unsigned long prot, unsigned long pgoff, unsigned long flags
// 	pub unsafe fn getdents64	__x64_sys_getdents64	fs/readdir.c:389		unsigned int fd, struct linux_dirent64 *dirent, unsigned int count
// 	pub unsafe fn set_tid_address	__x64_sys_set_tid_address	kernel/fork.c:1940		int *tidptr
// 	pub unsafe fn restart_syscall	__x64_sys_restart_syscall	kernel/signal.c:3177		void
// 	pub unsafe fn semtimedop	__x64_sys_semtimedop	ipc/sem.c:2268	SYSVIPC	int semid, struct sembuf *tsops, unsigned int nsops, const struct __kernel_timespec *timeout
// 	pub unsafe fn fadvise64	__x64_sys_fadvise64	mm/fadvise.c:208	ADVISE_SYSCALLS	int fd, loff_t offset, size_t len, int advice
// 	pub unsafe fn timer_create	__x64_sys_timer_create	kernel/time/posix-timers.c:480	POSIX_TIMERS	const clockid_t which_clock, struct sigevent *timer_event_spec, timer_t *created_timer_id
// 	pub unsafe fn timer_settime	__x64_sys_timer_settime	kernel/time/posix-timers.c:914	POSIX_TIMERS	timer_t timer_id, int flags, const struct __kernel_itimerspec *new_setting, struct __kernel_itimerspec *old_setting
// 	pub unsafe fn timer_gettime	__x64_sys_timer_gettime	kernel/time/posix-timers.c:676	POSIX_TIMERS	timer_t timer_id, struct __kernel_itimerspec *setting
// 	pub unsafe fn timer_getoverrun	__x64_sys_timer_getoverrun	kernel/time/posix-timers.c:724	POSIX_TIMERS	timer_t timer_id
// 	pub unsafe fn timer_delete	__x64_sys_timer_delete	kernel/time/posix-timers.c:994	POSIX_TIMERS	timer_t timer_id
// 	pub unsafe fn clock_settime	__x64_sys_clock_settime	kernel/time/posix-timers.c:1119		const clockid_t which_clock, const struct __kernel_timespec *tp
// 	pub unsafe fn clock_gettime	__x64_sys_clock_gettime	kernel/time/posix-timers.c:1138		const clockid_t which_clock, struct __kernel_timespec *tp
// 	pub unsafe fn clock_getres	__x64_sys_clock_getres	kernel/time/posix-timers.c:1258		const clockid_t which_clock, struct __kernel_timespec *tp
// 	pub unsafe fn clock_nanosleep	__x64_sys_clock_nanosleep	kernel/time/posix-timers.c:1379		const clockid_t which_clock, int flags, const struct __kernel_timespec *rqtp, struct __kernel_timespec *rmtp
// 	pub unsafe fn exit_group	__x64_sys_exit_group	kernel/exit.c:1096		int error_code
// 	pub unsafe fn epoll_wait	__x64_sys_epoll_wait	fs/eventpoll.c:2487	EPOLL	int epfd, struct epoll_event *events, int maxevents, int timeout
// 	pub unsafe fn epoll_ctl	__x64_sys_epoll_ctl	fs/eventpoll.c:2436	EPOLL	int epfd, int op, int fd, struct epoll_event *event
// 	pub unsafe fn tgkill	__x64_sys_tgkill	kernel/signal.c:4144		pid_t tgid, pid_t pid, int sig
// 	pub unsafe fn utimes	__x64_sys_utimes	fs/utimes.c:204		char *filename, struct __kernel_old_timeval *utimes
// 	pub unsafe fn mbind	__x64_sys_mbind	mm/mempolicy.c:1607	NUMA	unsigned long start, unsigned long len, unsigned long mode, const unsigned long *nmask, unsigned long maxnode, unsigned int flags
// 	pub unsafe fn set_mempolicy	__x64_sys_set_mempolicy	mm/mempolicy.c:1634	NUMA	int mode, const unsigned long *nmask, unsigned long maxnode
// 	pub unsafe fn get_mempolicy	__x64_sys_get_mempolicy	mm/mempolicy.c:1764	NUMA	int *policy, unsigned long *nmask, unsigned long maxnode, unsigned long addr, unsigned long flags
// 	pub unsafe fn mq_open	__x64_sys_mq_open	ipc/mqueue.c:944	POSIX_MQUEUE	const char *u_name, int oflag, umode_t mode, struct mq_attr *u_attr
// 	pub unsafe fn mq_unlink	__x64_sys_mq_unlink	ipc/mqueue.c:954	POSIX_MQUEUE	const char *u_name
// 	pub unsafe fn mq_timedsend	__x64_sys_mq_timedsend	ipc/mqueue.c:1258	POSIX_MQUEUE	mqd_t mqdes, const char *u_msg_ptr, size_t msg_len, unsigned int msg_prio, const struct __kernel_timespec *u_abs_timeout
// 	pub unsafe fn mq_timedreceive	__x64_sys_mq_timedreceive	ipc/mqueue.c:1272	POSIX_MQUEUE	mqd_t mqdes, char *u_msg_ptr, size_t msg_len, unsigned int *u_msg_prio, const struct __kernel_timespec *u_abs_timeout
// 	pub unsafe fn mq_notify	__x64_sys_mq_notify	ipc/mqueue.c:1400	POSIX_MQUEUE	mqd_t mqdes, const struct sigevent *u_notification
// 	pub unsafe fn mq_getsetattr	__x64_sys_mq_getsetattr	ipc/mqueue.c:1452	POSIX_MQUEUE	mqd_t mqdes, const struct mq_attr *u_mqstat, struct mq_attr *u_omqstat
// 	pub unsafe fn kexec_load	__x64_sys_kexec_load	kernel/kexec.c:242	KEXEC	unsigned long entry, unsigned long nr_segments, struct kexec_segment *segments, unsigned long flags
// 	pub unsafe fn waitid	__x64_sys_waitid	kernel/exit.c:1782		int which, pid_t upid, struct siginfo *infop, int options, struct rusage *ru
// 	pub unsafe fn add_key	__x64_sys_add_key	security/keys/keyctl.c:74	KEYS	const char *_type, const char *_description, const void *_payload, size_t plen, key_serial_t ringid
// 	pub unsafe fn request_key	__x64_sys_request_key	security/keys/keyctl.c:167	KEYS	const char *_type, const char *_description, const char *_callout_info, key_serial_t destringid
// 	pub unsafe fn keyctl	__x64_sys_keyctl	security/keys/keyctl.c:1874	KEYS	int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5
// 	pub unsafe fn ioprio_set	__x64_sys_ioprio_set	block/ioprio.c:69	BLOCK	int which, int who, int ioprio
// 	pub unsafe fn ioprio_get	__x64_sys_ioprio_get	block/ioprio.c:184	BLOCK	int which, int who
// 	pub unsafe fn inotify_init	__x64_sys_inotify_init	fs/notify/inotify/inotify_user.c:724	INOTIFY_USER	void
// 	pub unsafe fn inotify_add_watch	__x64_sys_inotify_add_watch	fs/notify/inotify/inotify_user.c:729	INOTIFY_USER	int fd, const char *pathname, u32 mask
// 	pub unsafe fn inotify_rm_watch	__x64_sys_inotify_rm_watch	fs/notify/inotify/inotify_user.c:786	INOTIFY_USER	int fd, __s32 wd
// 	pub unsafe fn migrate_pages	__x64_sys_migrate_pages	mm/mempolicy.c:1727	MIGRATION	pid_t pid, unsigned long maxnode, const unsigned long *old_nodes, const unsigned long *new_nodes
// 	pub unsafe fn openat	__x64_sys_openat	fs/open.c:1428		int dfd, const char *filename, int flags, umode_t mode
// 	pub unsafe fn mkdirat	__x64_sys_mkdirat	fs/namei.c:4347		int dfd, const char *pathname, umode_t mode
// 	pub unsafe fn mknodat	__x64_sys_mknodat	fs/namei.c:4264		int dfd, const char *filename, umode_t mode, unsigned int dev
// 	pub unsafe fn fchownat	__x64_sys_fchownat	fs/open.c:821		int dfd, const char *filename, uid_t user, gid_t group, int flag
// 	pub unsafe fn futimesat	__x64_sys_futimesat	fs/utimes.c:198		int dfd, const char *filename, struct __kernel_old_timeval *utimes
// 	pub unsafe fn newfstatat	__x64_sys_newfstatat	fs/stat.c:524		int dfd, const char *filename, struct stat *statbuf, int flag
// 	pub unsafe fn unlinkat	__x64_sys_unlinkat	fs/namei.c:4623		int dfd, const char *pathname, int flag
// 	pub unsafe fn renameat	__x64_sys_renameat	fs/namei.c:5262		int olddfd, const char *oldname, int newdfd, const char *newname
// 	pub unsafe fn linkat	__x64_sys_linkat	fs/namei.c:4888		int olddfd, const char *oldname, int newdfd, const char *newname, int flags
// 	pub unsafe fn symlinkat	__x64_sys_symlinkat	fs/namei.c:4708		const char *oldname, int newdfd, const char *newname
// 	pub unsafe fn readlinkat	__x64_sys_readlinkat	fs/stat.c:590		int dfd, const char *pathname, char *buf, int bufsiz
// 	pub unsafe fn fchmodat	__x64_sys_fchmodat	fs/open.c:702		int dfd, const char *filename, umode_t mode
// 	pub unsafe fn faccessat	__x64_sys_faccessat	fs/open.c:531		int dfd, const char *filename, int mode
// 	pub unsafe fn pselect6	__x64_sys_pselect6	fs/select.c:793		int n, fd_set *inp, fd_set *outp, fd_set *exp, struct __kernel_timespec *tsp, void *sig
// 	pub unsafe fn ppoll	__x64_sys_ppoll	fs/select.c:1095		struct pollfd *ufds, unsigned int nfds, struct __kernel_timespec *tsp, const sigset_t *sigmask, size_t sigsetsize
// 	pub unsafe fn unshare	__x64_sys_unshare	kernel/fork.c:3402		unsigned long unshare_flags
// 	pub unsafe fn set_robust_list	__x64_sys_set_robust_list	kernel/futex/syscalls.c:28	FUTEX	struct robust_list_head *head, size_t len
// 	pub unsafe fn get_robust_list	__x64_sys_get_robust_list	kernel/futex/syscalls.c:48	FUTEX	int pid, struct robust_list_head **head_ptr, size_t *len_ptr
// 	pub unsafe fn splice	__x64_sys_splice	fs/splice.c:1621		int fd_in, loff_t *off_in, int fd_out, loff_t *off_out, size_t len, unsigned int flags
// 	pub unsafe fn tee	__x64_sys_tee	fs/splice.c:1988		int fdin, int fdout, size_t len, unsigned int flags
// 	pub unsafe fn sync_file_range	__x64_sys_sync_file_range	fs/sync.c:363		int fd, loff_t offset, loff_t nbytes, unsigned int flags
// 	pub unsafe fn vmsplice	__x64_sys_vmsplice	fs/splice.c:1583		int fd, const struct iovec *uiov, unsigned long nr_segs, unsigned int flags
// 	pub unsafe fn move_pages	__x64_sys_move_pages	mm/migrate.c:2564	MIGRATION	pid_t pid, unsigned long nr_pages, const void **pages, const int *nodes, int *status, int flags
// 	pub unsafe fn utimensat	__x64_sys_utimensat	fs/utimes.c:143		int dfd, const char *filename, struct __kernel_timespec *utimes, int flags
// 	pub unsafe fn epoll_pwait	__x64_sys_epoll_pwait	fs/eventpoll.c:2521	EPOLL	int epfd, struct epoll_event *events, int maxevents, int timeout, const sigset_t *sigmask, size_t sigsetsize
// 	pub unsafe fn signalfd	__x64_sys_signalfd	fs/signalfd.c:319	SIGNALFD	int ufd, sigset_t *user_mask, size_t sizemask
// 	pub unsafe fn timerfd_create	__x64_sys_timerfd_create	fs/timerfd.c:395		int clockid, int flags
// 	pub unsafe fn eventfd	__x64_sys_eventfd	fs/eventfd.c:429		unsigned int count
// 	pub unsafe fn fallocate	__x64_sys_fallocate	fs/open.c:354		int fd, int mode, loff_t offset, loff_t len
// 	pub unsafe fn timerfd_settime	__x64_sys_timerfd_settime	fs/timerfd.c:560		int ufd, int flags, const struct __kernel_itimerspec *utmr, struct __kernel_itimerspec *otmr
// 	pub unsafe fn timerfd_gettime	__x64_sys_timerfd_gettime	fs/timerfd.c:578		int ufd, struct __kernel_itimerspec *otmr
// 	pub unsafe fn accept4	__x64_sys_accept4	net/socket.c:2014	NET	int fd, struct sockaddr *upeer_sockaddr, int *upeer_addrlen, int flags
// 	pub unsafe fn signalfd4	__x64_sys_signalfd4	fs/signalfd.c:307	SIGNALFD	int ufd, sigset_t *user_mask, size_t sizemask, int flags
// 	pub unsafe fn eventfd2	__x64_sys_eventfd2	fs/eventfd.c:424		unsigned int count, int flags
// 	pub unsafe fn epoll_create1	__x64_sys_epoll_create1	fs/eventpoll.c:2251	EPOLL	int flags
// 	pub unsafe fn dup3	__x64_sys_dup3	fs/file.c:1378		unsigned int oldfd, unsigned int newfd, int flags
// 	pub unsafe fn pipe2	__x64_sys_pipe2	fs/pipe.c:1040		int *fildes, int flags
// 	pub unsafe fn inotify_init1	__x64_sys_inotify_init1	fs/notify/inotify/inotify_user.c:719	INOTIFY_USER	int flags
// 	pub unsafe fn preadv	__x64_sys_preadv	fs/read_write.c:1167		unsigned long fd, const struct iovec *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h
// 	pub unsafe fn pwritev	__x64_sys_pwritev	fs/read_write.c:1187		unsigned long fd, const struct iovec *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h
// 	pub unsafe fn rt_tgsigqueueinfo	__x64_sys_rt_tgsigqueueinfo	kernel/signal.c:4228		pid_t tgid, pid_t pid, int sig, siginfo_t *uinfo
// 	pub unsafe fn perf_event_open	__x64_sys_perf_event_open	kernel/events/core.c:12721	PERF_EVENTS	struct perf_event_attr *attr_uptr, pid_t pid, int cpu, int group_fd, unsigned long flags
// 	pub unsafe fn recvmmsg	__x64_sys_recvmmsg	net/socket.c:3030	NET	int fd, struct mmsghdr *mmsg, unsigned int vlen, unsigned int flags, struct __kernel_timespec *timeout
// 	pub unsafe fn fanotify_init	__x64_sys_fanotify_init	fs/notify/fanotify/fanotify_user.c:1405	FANOTIFY	unsigned int flags, unsigned int event_f_flags
// 	pub unsafe fn fanotify_mark	__x64_sys_fanotify_mark	fs/notify/fanotify/fanotify_user.c:1913	FANOTIFY	int fanotify_fd, unsigned int flags, __u64 mask, int dfd, const char *pathname
// 	pub unsafe fn prlimit64	__x64_sys_prlimit64	kernel/sys.c:1693		pid_t pid, unsigned int resource, const struct rlimit64 *new_rlim, struct rlimit64 *old_rlim
// 	pub unsafe fn name_to_handle_at	__x64_sys_name_to_handle_at	fs/fhandle.c:129	FHANDLE	int dfd, const char *name, struct file_handle *handle, void *mnt_id, int flag
// 	pub unsafe fn open_by_handle_at	__x64_sys_open_by_handle_at	fs/fhandle.c:437	FHANDLE	int mountdirfd, struct file_handle *handle, int flags
// 	pub unsafe fn clock_adjtime	__x64_sys_clock_adjtime	kernel/time/posix-timers.c:1168		const clockid_t which_clock, struct __kernel_timex *utx
// 	pub unsafe fn syncfs	__x64_sys_syncfs	fs/sync.c:149		int fd
// 	pub unsafe fn sendmmsg	__x64_sys_sendmmsg	net/socket.c:2750	NET	int fd, struct mmsghdr *mmsg, unsigned int vlen, unsigned int flags
// 	pub unsafe fn setns	__x64_sys_setns	kernel/nsproxy.c:546		int fd, int flags
// 	pub unsafe fn getcpu	__x64_sys_getcpu	kernel/sys.c:2819		unsigned *cpup, unsigned *nodep, struct getcpu_cache *unused
// 	pub unsafe fn process_vm_readv	__x64_sys_process_vm_readv	mm/process_vm_access.c:292	CROSS_MEMORY_ATTACH	pid_t pid, const struct iovec *lvec, unsigned long liovcnt, const struct iovec *rvec, unsigned long riovcnt, unsigned long flags
// 	pub unsafe fn process_vm_writev	__x64_sys_process_vm_writev	mm/process_vm_access.c:299	CROSS_MEMORY_ATTACH	pid_t pid, const struct iovec *lvec, unsigned long liovcnt, const struct iovec *rvec, unsigned long riovcnt, unsigned long flags
// 	pub unsafe fn kcmp	__x64_sys_kcmp	kernel/kcmp.c:135	KCMP	pid_t pid1, pid_t pid2, int type, unsigned long idx1, unsigned long idx2
// 	pub unsafe fn finit_module	__x64_sys_finit_module	kernel/module/main.c:3587	MODULES	int fd, const char *uargs, int flags
// 	pub unsafe fn sched_setattr	__x64_sys_sched_setattr	kernel/sched/syscalls.c:991		pid_t pid, struct sched_attr *uattr, unsigned int flags
// 	pub unsafe fn sched_getattr	__x64_sys_sched_getattr	kernel/sched/syscalls.c:1091		pid_t pid, struct sched_attr *uattr, unsigned int usize, unsigned int flags
// 	pub unsafe fn renameat2	__x64_sys_renameat2	fs/namei.c:5255		int olddfd, const char *oldname, int newdfd, const char *newname, unsigned int flags
// 	pub unsafe fn seccomp	__x64_sys_seccomp	kernel/seccomp.c:2089	SECCOMP	unsigned int op, unsigned int flags, void *uargs
// 	pub unsafe fn getrandom	__x64_sys_getrandom	drivers/char/random.c:1388		char *ubuf, size_t len, unsigned int flags
// 	pub unsafe fn memfd_create	__x64_sys_memfd_create	mm/memfd.c:330	MEMFD_CREATE	const char *uname, unsigned int flags
// 	pub unsafe fn kexec_file_load	__x64_sys_kexec_file_load	kernel/kexec_file.c:332	KEXEC_FILE	int kernel_fd, int initrd_fd, unsigned long cmdline_len, const char *cmdline_ptr, unsigned long flags
// 	pub unsafe fn bpf	__x64_sys_bpf	kernel/bpf/syscall.c:5895	BPF_SYSCALL	int cmd, union bpf_attr *uattr, unsigned int size
// 	pub unsafe fn execveat	__x64_sys_execveat	fs/exec.c:2102		int fd, const char *filename, const char *const *argv, const char *const *envp, int flags
// 	pub unsafe fn userfaultfd	__x64_sys_userfaultfd	fs/userfaultfd.c:2155	USERFAULTFD	int flags
// 	pub unsafe fn membarrier	__x64_sys_membarrier	kernel/sched/membarrier.c:625	MEMBARRIER	int cmd, unsigned int flags, int cpu_id
// 	pub unsafe fn mlock2	__x64_sys_mlock2	mm/mlock.c:664	MMU	unsigned long start, size_t len, int flags
// 	pub unsafe fn copy_file_range	__x64_sys_copy_file_range	fs/read_write.c:1637		int fd_in, loff_t *off_in, int fd_out, loff_t *off_out, size_t len, unsigned int flags
// 	pub unsafe fn preadv2	__x64_sys_preadv2	fs/read_write.c:1175		unsigned long fd, const struct iovec *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h, rwf_t flags
// 	pub unsafe fn pwritev2	__x64_sys_pwritev2	fs/read_write.c:1195		unsigned long fd, const struct iovec *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h, rwf_t flags
// 	pub unsafe fn pkey_mprotect	__x64_sys_pkey_mprotect	mm/mprotect.c:866	X86_INTEL_MEMORY_PROTECTION_KEYS	unsigned long start, size_t len, unsigned long prot, int pkey
// 	pub unsafe fn pkey_alloc	__x64_sys_pkey_alloc	mm/mprotect.c:872	X86_INTEL_MEMORY_PROTECTION_KEYS	unsigned long flags, unsigned long init_val
// 	pub unsafe fn pkey_free	__x64_sys_pkey_free	mm/mprotect.c:902	X86_INTEL_MEMORY_PROTECTION_KEYS	int pkey
// 	pub unsafe fn statx	__x64_sys_statx	fs/stat.c:796		int dfd, const char *filename, unsigned flags, unsigned int mask, struct statx *buffer
// 	pub unsafe fn io_pgetevents	__x64_sys_io_pgetevents	fs/aio.c:2275	AIO	aio_context_t ctx_id, long min_nr, long nr, struct io_event *events, struct __kernel_timespec *timeout, const struct __aio_sigset *usig
// 	pub unsafe fn rseq	__x64_sys_rseq	kernel/rseq.c:365	RSEQ	struct rseq *rseq, u32 rseq_len, int flags, u32 sig
// 	pub unsafe fn uretprobe	__x64_sys_uretprobe	arch/x86/kernel/uprobes.c:367		void
// 	pub unsafe fn pidfd_send_signal	__x64_sys_pidfd_send_signal	kernel/signal.c:4026		int pidfd, int sig, siginfo_t *info, unsigned int flags
// 	pub unsafe fn io_uring_setup	__x64_sys_io_uring_setup	io_uring/io_uring.c:3828	IO_URING	u32 entries, struct io_uring_params *params
// 	pub unsafe fn io_uring_enter	__x64_sys_io_uring_enter	io_uring/io_uring.c:3326	IO_URING	unsigned int fd, u32 to_submit, u32 min_complete, u32 flags, const void *argp, size_t argsz
// 	pub unsafe fn io_uring_register	__x64_sys_io_uring_register	io_uring/register.c:897	IO_URING	unsigned int fd, unsigned int opcode, void *arg, unsigned int nr_args
// 	pub unsafe fn open_tree	__x64_sys_open_tree	fs/namespace.c:2843		int dfd, const char *filename, unsigned flags
// 	pub unsafe fn move_mount	__x64_sys_move_mount	fs/namespace.c:4230		int from_dfd, const char *from_pathname, int to_dfd, const char *to_pathname, unsigned int flags
// 	pub unsafe fn fsopen	__x64_sys_fsopen	fs/fsopen.c:114		const char *_fs_name, unsigned int flags
// 	pub unsafe fn fsconfig	__x64_sys_fsconfig	fs/fsopen.c:344		int fd, unsigned int cmd, const char *_key, const void *_value, int aux
// 	pub unsafe fn fsmount	__x64_sys_fsmount	fs/namespace.c:4106		int fs_fd, unsigned int flags, unsigned int attr_flags
// 	pub unsafe fn fspick	__x64_sys_fspick	fs/fsopen.c:157		int dfd, const char *path, unsigned int flags
// 	pub unsafe fn pidfd_open	__x64_sys_pidfd_open	kernel/pid.c:626		pid_t pid, unsigned int flags
// 	pub unsafe fn clone3	__x64_sys_clone3	kernel/fork.c:3089		struct clone_args *uargs, size_t size
// 	pub unsafe fn close_range	__x64_sys_close_range	fs/file.c:769		unsigned int fd, unsigned int max_fd, unsigned int flags
// 	pub unsafe fn openat2	__x64_sys_openat2	fs/open.c:1436		int dfd, const char *filename, struct open_how *how, size_t usize
// 	pub unsafe fn pidfd_getfd	__x64_sys_pidfd_getfd	kernel/pid.c:743		int pidfd, int fd, unsigned int flags
// 	pub unsafe fn faccessat2	__x64_sys_faccessat2	fs/open.c:536		int dfd, const char *filename, int mode, int flags
// 	pub unsafe fn process_madvise	__x64_sys_process_madvise	mm/madvise.c:1742	ADVISE_SYSCALLS	int pidfd, const struct iovec *vec, size_t vlen, int behavior, unsigned int flags
// 	pub unsafe fn epoll_pwait2	__x64_sys_epoll_pwait2	fs/eventpoll.c:2532	EPOLL	int epfd, struct epoll_event *events, int maxevents, const struct __kernel_timespec *timeout, const sigset_t *sigmask, size_t sigsetsize
// 	pub unsafe fn mount_setattr	__x64_sys_mount_setattr	fs/namespace.c:4797		int dfd, const char *path, unsigned int flags, struct mount_attr *uattr, size_t usize
// 	pub unsafe fn quotactl_fd	__x64_sys_quotactl_fd	fs/quota/quota.c:973	QUOTACTL	unsigned int fd, unsigned int cmd, qid_t id, void *addr
// 	pub unsafe fn landlock_create_ruleset	__x64_sys_landlock_create_ruleset	security/landlock/syscalls.c:179	SECURITY_LANDLOCK	const struct landlock_ruleset_attr *const attr, const size_t size, const __u32 flags
// 	pub unsafe fn landlock_add_rule	__x64_sys_landlock_add_rule	security/landlock/syscalls.c:397	SECURITY_LANDLOCK	const int ruleset_fd, const enum landlock_rule_type rule_type, const void *const rule_attr, const __u32 flags
// 	pub unsafe fn landlock_restrict_self	__x64_sys_landlock_restrict_self	security/landlock/syscalls.c:456	SECURITY_LANDLOCK	const int ruleset_fd, const __u32 flags
// 	pub unsafe fn memfd_secret	__x64_sys_memfd_secret	mm/secretmem.c:233	SECRETMEM	unsigned int flags
// 	pub unsafe fn process_mrelease	__x64_sys_process_mrelease	mm/oom_kill.c:1198	MMU	int pidfd, unsigned int flags
// 	pub unsafe fn futex_waitv	__x64_sys_futex_waitv	kernel/futex/syscalls.c:290	FUTEX	struct futex_waitv *waiters, unsigned int nr_futexes, unsigned int flags, struct __kernel_timespec *timeout, clockid_t clockid
// 	pub unsafe fn set_mempolicy_home_node	__x64_sys_set_mempolicy_home_node	mm/mempolicy.c:1540	NUMA	unsigned long start, unsigned long len, unsigned long home_node, unsigned long flags
// 	pub unsafe fn cachestat	__x64_sys_cachestat	mm/filemap.c:4412	CACHESTAT_SYSCALL	unsigned int fd, struct cachestat_range *cstat_range, struct cachestat *cstat, unsigned int flags
// 	pub unsafe fn fchmodat2	__x64_sys_fchmodat2	fs/open.c:696		int dfd, const char *filename, umode_t mode, unsigned int flags
// 	pub unsafe fn map_shadow_stack	__x64_sys_map_shadow_stack	arch/x86/kernel/shstk.c:505	X86_USER_SHADOW_STACK	unsigned long addr, unsigned long size, unsigned int flags
// 	pub unsafe fn futex_wake	__x64_sys_futex_wake	kernel/futex/syscalls.c:338	FUTEX	void *uaddr, unsigned long mask, int nr, unsigned int flags
// 	pub unsafe fn futex_wait	__x64_sys_futex_wait	kernel/futex/syscalls.c:370	FUTEX	void *uaddr, unsigned long val, unsigned long mask, unsigned int flags, struct __kernel_timespec *timeout, clockid_t clockid
// 	pub unsafe fn futex_requeue	__x64_sys_futex_requeue	kernel/futex/syscalls.c:414	FUTEX	struct futex_waitv *waiters, unsigned int flags, int nr_wake, int nr_requeue
// 	pub unsafe fn statmount	__x64_sys_statmount	fs/namespace.c:5448		const struct mnt_id_req *req, struct statmount *buf, size_t bufsize, unsigned int flags
// 	pub unsafe fn listmount	__x64_sys_listmount	fs/namespace.c:5555		const struct mnt_id_req *req, u64 *mnt_ids, size_t nr_mnt_ids, unsigned int flags
// 	pub unsafe fn lsm_get_self_attr	__x64_sys_lsm_get_self_attr	security/lsm_syscalls.c:77	SECURITY	unsigned int attr, struct lsm_ctx *ctx, u32 *size, u32 flags
// 	pub unsafe fn lsm_set_self_attr	__x64_sys_lsm_set_self_attr	security/lsm_syscalls.c:55	SECURITY	unsigned int attr, struct lsm_ctx *ctx, u32 size, u32 flags
// 	pub unsafe fn lsm_list_modules	__x64_sys_lsm_list_modules	security/lsm_syscalls.c:96	SECURITY	u64 *ids, u32 *size, u32 flags
// 	pub unsafe fn mseal	__x64_sys_mseal	mm/mseal.c:265		unsigned long start, size_t len, unsigned long flags
// 	pub unsafe fn setxattrat	__x64_sys_setxattrat	fs/xattr.c:719		int dfd, const char *pathname, unsigned int at_flags, const char *name, const struct xattr_args *uargs, size_t usize
// 	pub unsafe fn getxattrat	__x64_sys_getxattrat	fs/xattr.c:863		int dfd, const char *pathname, unsigned int at_flags, const char *name, struct xattr_args *uargs, size_t usize
// 	pub unsafe fn listxattrat	__x64_sys_listxattrat	fs/xattr.c:991		int dfd, const char *pathname, unsigned int at_flags, char *list, size_t size
// 	pub unsafe fn removexattrat	__x64_sys_removexattrat	fs/xattr.c:1091		int dfd, const char *pathname, unsigned int at_flags, const char *name
// 362  syscalls

// Copyright © 2023-2024 Marco Bonelli — Licensed under the GNU General Public License v3.0
