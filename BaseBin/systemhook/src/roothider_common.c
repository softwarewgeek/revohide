#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/syscall.h>
#include <sys/proc_info.h>
#include <time.h>
#include <dispatch/dispatch.h>
#include <dlfcn.h>
#include <objc/runtime.h>

#include "roothider.h"

pid_t __getppid()
{
	int32_t opt[4] = {
		CTL_KERN,
		KERN_PROC,
		KERN_PROC_PID,
		getpid(),
	};
	struct kinfo_proc info={0};
	size_t len = sizeof(struct kinfo_proc);
	if(sysctl(opt, 4, &info, &len, NULL, 0) == 0) {
		if((info.kp_proc.p_flag & P_TRACED) != 0) {
			return info.kp_proc.p_oppid;
		}
	}

    struct proc_bsdinfo procInfo;
	//some process may be killed by sandbox if call systme getppid() so try this first
	if (proc_pidinfo(getpid(), PROC_PIDTBSDINFO, 0, &procInfo, sizeof(procInfo)) == sizeof(procInfo)) {
		return procInfo.pbi_ppid;
	}

	return getppid();
}

#define APP_PATH_PREFIX "/private/var/containers/Bundle/Application/"
char* getAppUUIDPath(const char* path)
{
    if(!path) return NULL;

    char abspath[PATH_MAX];
    if(!realpath(path, abspath)) return NULL;

    if(strncmp(abspath, APP_PATH_PREFIX, sizeof(APP_PATH_PREFIX)-1) != 0)
        return NULL;

    char* p1 = abspath + sizeof(APP_PATH_PREFIX)-1;
    char* p2 = strchr(p1, '/');
    if(!p2) return NULL;

    //is normal app or jailbroken app/daemon?
    if((p2 - p1) != (sizeof("xxxxxxxx-xxxx-xxxx-yxxx-xxxxxxxxxxxx")-1))
        return NULL;

	*p2 = '\0';

	return strdup(abspath);
}

bool isRemovableBundlePath(const char* path)
{
    const char* uuidpath = getAppUUIDPath(path);
	if(!uuidpath) return false;
	free((void*)uuidpath);
	return true;
}

bool hasTrollstoreMarker(const char* path)
{
    char* uuidpath = getAppUUIDPath(path);
	if(!uuidpath) return false;

	char* markerpath=NULL;
	asprintf(&markerpath, "%s/_TrollStore", uuidpath);

	int ret = access(markerpath, F_OK);
    if(ret != 0) {
        free((void*)markerpath); markerpath = NULL;
        asprintf(&markerpath, "%s/_TrollStoreLite", uuidpath);
        ret = access(markerpath, F_OK);
    }

    free((void*)markerpath);
	free((void*)uuidpath);

	return ret==0;
}

/* the only reason this function exists is to allow Choicy
	 to block systemhook injection for both stock daemons and normal apps (but not for their child processes) */
bool allowInjectWithSafeMode(const char* path)
{
	if(getpid() != 1) {
		return true;
	}

	if(isRemovableBundlePath(path))
	{
		if(hasTrollstoreMarker(path)) {
			//always inject into trollstored apps unless we blacklist it in roothide manager
			return true;
		} else {
			return false;
		}
	}

	struct statfs fs = {0};
	if(statfs(path, &fs) == 0) {
		if(strcmp(fs.f_mntonname, "/") == 0) {
			// disallow injecting into system process if Choicy blocked it
			return false;
		}
	}

	return true;
}


int __sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, const void *newp, size_t newlen);
int syscall__sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, const void *newp, size_t newlen) {
	return syscall(SYS_sysctl, name, namelen, oldp, oldlenp, newp, newlen);
}

// ─── Respring-hide logging via POSIX shared memory ───────────────────────────
// Stored entirely in RAM — no file in /var/mobile, /tmp, or anywhere Revolut
// might scan. The kernel backs /revohide in anonymous memory; it disappears on
// reboot. Dopamine's log viewer maps the same segment to display entries.

#define RH_SHM_NAME  "/revohide"
#define RH_SHM_TOTAL (1 << 18)          // 256 KB
#define RH_BUF_CAP   (RH_SHM_TOTAL - 8) // minus header

typedef struct {
	volatile uint32_t write_pos;  // next byte to write (monotonic within buf)
	volatile uint32_t reserved;
	char buf[RH_SHM_TOTAL - 8];
} rh_shm_t;

static rh_shm_t *rh_shm_map(void)
{
	static rh_shm_t *ptr = NULL;
	if (ptr) return ptr;

	int fd = shm_open(RH_SHM_NAME, O_CREAT | O_RDWR, 0600);
	if (fd < 0) return NULL;

	struct stat st;
	if (fstat(fd, &st) == 0 && st.st_size == 0)
		ftruncate(fd, RH_SHM_TOTAL);

	void *m = mmap(NULL, RH_SHM_TOTAL, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	close(fd);
	if (m == MAP_FAILED) return NULL;
	ptr = (rh_shm_t *)m;
	return ptr;
}

static void rh_log(const char *fmt, ...)
{
	rh_shm_t *shm = rh_shm_map();
	if (!shm) return;

	char line[512];
	time_t now = time(NULL);
	struct tm *t = localtime(&now);
	char tbuf[16] = "??:??:??";
	if (t) strftime(tbuf, sizeof(tbuf), "%H:%M:%S", t);
	const char *prog = getprogname();
	int hlen = snprintf(line, sizeof(line), "[%s][%s:%d] ", tbuf, prog ? prog : "?", (int)getpid());
	if (hlen < 0) hlen = 0;

	va_list ap;
	va_start(ap, fmt);
	int blen = vsnprintf(line + hlen, (int)sizeof(line) - hlen, fmt, ap);
	va_end(ap);
	if (blen < 0) blen = 0;

	int total = hlen + blen;
	if (total >= (int)sizeof(line)) total = (int)sizeof(line) - 1;

	uint32_t pos = shm->write_pos;
	if (pos + (uint32_t)total + 1 > RH_BUF_CAP) {
		// Slide window: keep last half, discard oldest entries
		uint32_t keep = RH_BUF_CAP / 2;
		uint32_t from = pos > keep ? pos - keep : 0;
		// Advance 'from' to next newline so we don't start mid-line
		while (from < pos && shm->buf[from] != '\n') from++;
		if (from < pos) from++;
		uint32_t newlen = pos - from;
		memmove(shm->buf, shm->buf + from, newlen);
		pos = newlen;
		shm->write_pos = pos;
	}

	memcpy(shm->buf + pos, line, total);
	pos += total;
	shm->buf[pos] = '\0';
	shm->write_pos = pos;
}

// ─── Respring-hiding helpers ──────────────────────────────────────────────────

static time_t rh_get_real_boottime(void) {
	struct timeval bt = {0};
	size_t sz = sizeof(bt);
	int mib[] = {CTL_KERN, KERN_BOOTTIME};
	syscall__sysctl(mib, 2, &bt, &sz, NULL, 0);
	return bt.tv_sec;
}

static time_t rh_get_self_starttime(void) {
	static time_t cached = 0;
	if (cached) return cached;
	struct kinfo_proc info = {0};
	size_t sz = sizeof(info);
	int mib[] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, (int)getpid()};
	if (syscall__sysctl(mib, 4, &info, &sz, NULL, 0) == 0)
		cached = info.kp_proc.p_starttime.tv_sec;
	return cached;
}

// Returns gap between our start and real kernel boot. 0 = no respring detected.
static long rh_respring_offset(void) {
	time_t our_start = rh_get_self_starttime();
	time_t boot = rh_get_real_boottime();
	if (!our_start || !boot) return 0;
	long gap = (long)our_start - (long)boot;
	return (gap >= 60) ? gap : 0;
}

// Find the most recent respring epoch by reading SpringBoard's start time.
// SpringBoard is killed and restarted on EVERY respring, so its start time
// always reflects the latest respring — even after multiple Sileo-triggered
// resprings. Using the earliest post-boot process would anchor to the FIRST
// respring and expose large gaps after subsequent resprings.
static time_t rh_find_respring_epoch(void) {
	static time_t cached = 0;
	if (cached) return cached;

	int mib[] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
	size_t sz = 0;
	syscall__sysctl(mib, 3, NULL, &sz, NULL, 0);
	if (!sz) return 0;

	struct kinfo_proc *procs = malloc(sz);
	if (!procs) return 0;

	if (syscall__sysctl(mib, 3, procs, &sz, NULL, 0) != 0) {
		free(procs);
		return 0;
	}

	time_t real_boot = rh_get_real_boottime();
	size_t count = sz / sizeof(struct kinfo_proc);
	time_t springboard_start = 0;
	time_t max_start = 0; // fallback: latest post-respring process

	for (size_t i = 0; i < count; i++) {
		time_t ps = procs[i].kp_proc.p_starttime.tv_sec;
		if (ps < real_boot + 55) continue; // started within 55s of boot — not post-respring

		// Primary: find SpringBoard (the definitive respring marker)
		if (strncmp(procs[i].kp_proc.p_comm, "SpringBoard", 11) == 0) {
			springboard_start = ps;
		}

		// Fallback: track the latest cluster start time
		if (ps > max_start) max_start = ps;
	}

	free(procs);

	// Use SpringBoard's start if found; otherwise fall back to the latest
	// process cluster (handles edge cases where SpringBoard name differs)
	time_t result = springboard_start ? springboard_start : max_start;
	cached = result;
	return result;
}

// The timestamp we report as kern.boottime.
// Set 2 seconds before the earliest post-respring process so all process
// start times are naturally later than the "boot" — no per-process adjustment
// is needed and there's no inconsistency.
static time_t rh_fake_boottime(void) {
	static time_t cached = 0;
	if (cached) return cached;

	if (!rh_respring_offset()) return 0;

	time_t epoch = rh_find_respring_epoch();
	if (!epoch) {
		// Fallback: 5 seconds before our own start
		cached = rh_get_self_starttime() - 5;
	} else {
		cached = epoch - 2;
	}
	return cached;
}

// Seconds to subtract from raw monotonic/uptime values so they're consistent
// with our faked kern.boottime.
static long rh_uptime_adjustment(void) {
	time_t fake_boot = rh_fake_boottime();
	time_t real_boot = rh_get_real_boottime();
	if (!fake_boot || !real_boot) return 0;
	long adj = (long)(fake_boot - real_boot); // negative: fake_boot is later
	// adj is negative, meaning real uptime is larger — subtract its abs value
	return adj; // caller does: fake = real_ns + adj*NSEC_PER_SEC  (adj < 0)
}

// ─── NSProcessInfo.systemUptime hook (ObjC) ───────────────────────────────────

typedef double NSTimeInterval;
static NSTimeInterval (*orig_systemUptime)(id, SEL) = NULL;

static NSTimeInterval hook_systemUptime(id self, SEL _cmd)
{
	NSTimeInterval real = orig_systemUptime(self, _cmd);
	long adj = rh_uptime_adjustment(); // adj <= 0
	if (adj < 0) {
		NSTimeInterval fake = real + (NSTimeInterval)adj;
		if (fake < 1.0) fake = 1.0;
		rh_log("NSProcessInfo.systemUptime: real=%.1f fake=%.1f\n", real, fake);
		return fake;
	}
	return real;
}

void rh_hook_nsprocessinfo(void)
{
	if (!rh_respring_offset()) return;

	// Load libobjc at runtime via dlsym — systemhook.dylib has no libobjc linkage,
	// so we cannot call ObjC runtime functions directly at link time.
	void *libobjc = dlopen("/usr/lib/libobjc.A.dylib", RTLD_LAZY | RTLD_NOLOAD);
	if (!libobjc) return;

	typedef void *(*fn_objc_getClass)(const char *);
	typedef SEL  (*fn_sel_registerName)(const char *);
	typedef Method (*fn_class_getInstanceMethod)(Class, SEL);
	typedef IMP    (*fn_method_getImplementation)(Method);
	typedef void   (*fn_method_setImplementation)(Method, IMP);

	fn_objc_getClass            p_getClass  = (fn_objc_getClass)           dlsym(libobjc, "objc_getClass");
	fn_sel_registerName         p_selReg    = (fn_sel_registerName)         dlsym(libobjc, "sel_registerName");
	fn_class_getInstanceMethod  p_getMethod = (fn_class_getInstanceMethod)  dlsym(libobjc, "class_getInstanceMethod");
	fn_method_getImplementation p_getIMP    = (fn_method_getImplementation) dlsym(libobjc, "method_getImplementation");
	fn_method_setImplementation p_setIMP    = (fn_method_setImplementation) dlsym(libobjc, "method_setImplementation");

	if (!p_getClass || !p_selReg || !p_getMethod || !p_getIMP || !p_setIMP) return;

	Class cls = (Class)p_getClass("NSProcessInfo");
	if (!cls) return;
	SEL sel = p_selReg("systemUptime");
	Method m = p_getMethod(cls, sel);
	if (!m) return;

	IMP orig = p_getIMP(m);
	if (orig == (IMP)hook_systemUptime) return; // already hooked
	orig_systemUptime = (NSTimeInterval (*)(id, SEL))orig;
	p_setIMP(m, (IMP)hook_systemUptime);
	rh_log("rh_hook_nsprocessinfo: hooked, uptime_adj=%lds\n", rh_uptime_adjustment());
}

// ─── sysctl hook ─────────────────────────────────────────────────────────────

int __sysctl_hook(int *name, u_int namelen, void *oldp, size_t *oldlenp, const void *newp, size_t newlen)
{
	// Fake kern.boottime — the single most important respring indicator.
	// We return a timestamp just before the earliest post-respring process so
	// all KERN_PROC start times are naturally *after* the reported boot time.
	if (name && namelen == 2 && name[0] == CTL_KERN && name[1] == KERN_BOOTTIME) {
		time_t fake_boot = rh_fake_boottime();
		if (fake_boot > 0 && oldp && oldlenp && *oldlenp >= sizeof(struct timeval)) {
			struct timeval fake = {0};
			fake.tv_sec = fake_boot;
			*(struct timeval *)oldp = fake;
			*oldlenp = sizeof(struct timeval);
			rh_log("sysctl KERN_BOOTTIME: real=%ld fake=%ld\n",
				   (long)rh_get_real_boottime(), (long)fake_boot);
			return 0;
		}
	}

	// For KERN_PROC queries we let the real call through unchanged.
	// Because fake_boot is 2 seconds before the earliest post-respring process,
	// every running user-space process already has a start time > fake_boot.
	// No per-process adjustment is needed (and the old adjustment code introduced
	// an impossible inconsistency where processes appeared to predate the boot).

	static int cached_namelen = 0;
	static int cached_name[CTL_MAXNAME+2]={0};

	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		int mib[] = {0, 3}; //https://github.com/apple-oss-distributions/Libc/blob/899a3b2d52d95d75e05fb286a5e64975ec3de757/gen/FreeBSD/sysctlbyname.c#L24
		size_t buflen = sizeof(cached_name);
		const char* query = "security.mac.amfi.developer_mode_status";
		if(syscall__sysctl(mib, sizeof(mib)/sizeof(mib[0]), cached_name, &buflen, (void*)query, strlen(query))==0) {
			cached_namelen = buflen / sizeof(cached_name[0]);
		}
	});

	if(name && namelen && cached_namelen &&
	 namelen==cached_namelen && memcmp(cached_name, name, namelen*sizeof(name[0]))==0) {
		if(oldp && oldlenp && *oldlenp>=sizeof(int)) {
			*(int*)oldp = 1;
			*oldlenp = sizeof(int);
			return 0;
		}
	}

	return syscall__sysctl(name,namelen,oldp,oldlenp,newp,newlen);
}

int __sysctlbyname(const char *name, size_t namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
int syscall__sysctlbyname(const char *name, size_t namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen)
{
	return syscall(SYS_sysctlbyname, name, namelen, oldp, oldlenp, newp, newlen);
}
int __sysctlbyname_hook(const char *name, size_t namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen)
{
	if (name && namelen && strncmp(name, "kern.boottime", 13) == 0) {
		time_t fake_boot = rh_fake_boottime();
		if (fake_boot > 0 && oldp && oldlenp && *oldlenp >= sizeof(struct timeval)) {
			struct timeval fake = {0};
			fake.tv_sec = fake_boot;
			*(struct timeval *)oldp = fake;
			*oldlenp = sizeof(struct timeval);
			rh_log("sysctlbyname kern.boottime: real=%ld fake=%ld\n",
				   (long)rh_get_real_boottime(), (long)fake_boot);
			return 0;
		}
	}

	if(name && namelen && strncmp(name, "security.mac.amfi.developer_mode_status", namelen)==0) {
		if(oldp && oldlenp && *oldlenp>=sizeof(int)) {
			*(int*)oldp = 1;
			*oldlenp = sizeof(int);
			return 0;
		}
	}
	return syscall__sysctlbyname(name,namelen,oldp,oldlenp,newp,newlen);
}
