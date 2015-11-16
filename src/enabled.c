#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include "selinux_internal.h"
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include "policy.h"
#include "../../bionic/libc/include/sys/system_properties.h"

int is_selinux_enabled(void)
{
    	char tmp[PROP_VALUE_MAX];
	if (access("/sys/fs/selinux", F_OK) != 0) {
		/* SELinux is not compiled into the kernel, or has been disabled
		** via the kernel command line "selinux=0".
		**/
		return 0;
	}else if ((__system_property_get("ro.boot.selinux", tmp) > 0) && (strcmp(tmp, "disabled") == 0)) {
		/* SELinux is compiled into the kernel, but we've been told to disable it. */
		return 0;
	}
	/* init_selinuxmnt() gets called before this function. We
 	 * will assume that if a selinux file system is mounted, then
 	 * selinux is enabled. */
	return (selinux_mnt ? 1 : 0);
}

hidden_def(is_selinux_enabled)

/*
 * Function: is_selinux_mls_enabled()
 * Return:   1 on success
 *	     0 on failure
 */
int is_selinux_mls_enabled(void)
{
	char buf[20], path[PATH_MAX];
	int fd, ret, enabled = 0;

	if (!selinux_mnt)
		return enabled;

	snprintf(path, sizeof path, "%s/mls", selinux_mnt);
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return enabled;

	memset(buf, 0, sizeof buf);

	do {
		ret = read(fd, buf, sizeof buf - 1);
	} while (ret < 0 && errno == EINTR);
	close(fd);
	if (ret < 0)
		return enabled;

	if (!strcmp(buf, "1"))
		enabled = 1;

	return enabled;
}

hidden_def(is_selinux_mls_enabled)
