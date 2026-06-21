#include <stdio.h>
#include <unistd.h>
#include <libproc.h>
#include <sys/mount.h>
#include <sys/sysctl.h>
#include <sys/syscall.h>
#include <sys/proc_info.h>
#include <dispatch/dispatch.h>

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

// --- Respring-hiding helpers ---

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

// Returns the time offset between userspace reboot and real kernel boot.
// Returns 0 if no userspace reboot is detected (gap < 60s).
static long rh_respring_offset(void) {
	time_t our_start = rh_get_self_starttime();
	time_t boot = rh_get_real_boottime();
	if (!our_start || !boot) return 0;
	long gap = (long)our_start - (long)boot;
	return (gap >= 60) ? gap : 0;
}

// Adjust process start times in a kinfo_proc array to look like a clean boot.
static void rh_fix_proc_starttimes(struct kinfo_proc *procs, size_t count) {
	if (!procs || !count) return;
	long offset = rh_respring_offset();
	if (!offset) return;
	time_t our_start = rh_get_self_starttime();
	time_t boot = rh_get_real_boottime();
	for (size_t i = 0; i < count; i++) {
		time_t ps = procs[i].kp_proc.p_starttime.tv_sec;
		// Only touch processes that started around the userspace reboot (within 5 minutes).
		if (ps >= our_start - 300) {
			// Shift start time to be near real kernel boot instead.
			long relative = ps - our_start; // offset from userspace reboot
			time_t adjusted = boot + 5 + relative;
			procs[i].kp_proc.p_starttime.tv_sec = (adjusted > boot) ? adjusted : boot + 1;
			procs[i].kp_proc.p_starttime.tv_usec = 0;
		}
	}
}

// --- End respring-hiding helpers ---

int __sysctl_hook(int *name, u_int namelen, void *oldp, size_t *oldlenp, const void *newp, size_t newlen)
{
	// Hide respring: fake kern.boottime to match userspace reboot time
	if (name && namelen == 2 && name[0] == CTL_KERN && name[1] == KERN_BOOTTIME) {
		long offset = rh_respring_offset();
		if (offset > 0 && oldp && oldlenp && *oldlenp >= sizeof(struct timeval)) {
			struct timeval fake = {0};
			// Device "booted" 5 seconds before our process started
			fake.tv_sec = rh_get_self_starttime() - 5;
			*(struct timeval *)oldp = fake;
			*oldlenp = sizeof(struct timeval);
			return 0;
		}
	}

	// Hide respring: adjust process start times in KERN_PROC results
	if (name && namelen >= 3 && name[0] == CTL_KERN && name[1] == KERN_PROC &&
		(name[2] == KERN_PROC_ALL || name[2] == KERN_PROC_PID || name[2] == KERN_PROC_PGRP)) {
		int ret = syscall__sysctl(name, namelen, oldp, oldlenp, newp, newlen);
		if (ret == 0 && oldp && oldlenp && *oldlenp >= sizeof(struct kinfo_proc))
			rh_fix_proc_starttimes((struct kinfo_proc *)oldp, *oldlenp / sizeof(struct kinfo_proc));
		return ret;
	}

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
	// Hide respring: fake kern.boottime via sysctlbyname
	if (name && namelen && strncmp(name, "kern.boottime", namelen) == 0) {
		long offset = rh_respring_offset();
		if (offset > 0 && oldp && oldlenp && *oldlenp >= sizeof(struct timeval)) {
			struct timeval fake = {0};
			fake.tv_sec = rh_get_self_starttime() - 5;
			*(struct timeval *)oldp = fake;
			*oldlenp = sizeof(struct timeval);
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
