/**
 * This function is called from Golang.
 * cgo entry point.
 * MUST BE called in the C constructor.
 */


#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sched.h>
#include <errno.h>
#include <stdbool.h>
#include <dirent.h>
#include <syslog.h>
#include <stdarg.h>
#include <libgen.h>

#include <linux/limits.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#define errorf(fmt, ...) fprintf(stderr, "cgo: %s:%d [%s]: "fmt"\n", __FILE__, __LINE__, __func__, ##__VA_ARGS__)

// FIXME: check kernel cmdline to enable or disable this
#define debugf(fmt, ...) fprintf(stdout, "cgo: %s:%d [%s]: "fmt"\n", __FILE__, __LINE__, __func__, ##__VA_ARGS__)

static const char* old_rootfs_dir = ".old";

typedef int (*hookFunc)(void);

struct namespace {
	int         type;
	const char* name;
	hookFunc    hook;
};

struct sys_fs {
	char src[PATH_MAX];
	char dest[PATH_MAX];
	char fs_type[20];
	int flags;
};


/**
 * Set private propagation
 *
 * \param namespaces_path path to persistent namespaces
 *
 * \return 0 on success, 1 on failure
 */
static int mnt_private(void) {
	// mount root as private to not propagate events
	if (mount("none", "/", NULL, MS_REC|MS_PRIVATE, NULL) == -1) {
		errorf("Could not mount / as private: %s", strerror(errno));
		return 1;
	}
	return 0;
}

static const struct namespace supported_namespaces[] = {
	/* { .type = CLONE_NEWUSER,   .name = "user",   .hook = NULL, }, */
	/* { .type = CLONE_NEWCGROUP, .name = "cgroup", .hook = NULL, }, */
	{ .type = CLONE_NEWIPC,    .name = "ipc",    .hook = NULL, },
	{ .type = CLONE_NEWUTS,    .name = "uts",    .hook = NULL, },
	/* { .type = CLONE_NEWNET,    .name = "net",    .hook = NULL, }, */
	{ .type = CLONE_NEWPID,    .name = "pid",    .hook = NULL, },
	{ .type = CLONE_NEWNS,     .name = "mnt",    .hook = mnt_private, },
	{ .name = NULL }
};

static int new_rootfs(char *rootfs_path, size_t size) {
	// FIXME: /tmp ? "/agentXXXXXX"
	char new_rootfs_path[] = "/rootfs";
	char rootfs_dir[PATH_MAX] = { 0 };
	// FIXME: get the path using /proc/self/exec
	const char* agent_path = "/usr/bin/kata-agent";
	char new_agent_path[PATH_MAX] = {0};
	const char* rootfs_dirs[] = { "dev", "proc", "run", "sys", "tmp",
								  "usr", "usr/bin", old_rootfs_dir, NULL };

	/* if (mkdtemp(new_rootfs_path) == NULL) { */
	/* 	errorf("Could not create the new rootfs path: %s", strerror(errno)); */
	/* 	return -1; */
	/* } */

	debugf("New rootfs path: %s", new_rootfs_path);
	for (const char** d = rootfs_dirs; *d != NULL; d++) {
		snprintf(rootfs_dir, sizeof(rootfs_dir), "%s/%s", new_rootfs_path, *d);
		if (mkdir(rootfs_dir, S_IRWXU) == -1) {
			errorf("Could not create old rootfs: %s", strerror(errno));
			return -1;
		}
	}

	snprintf(new_agent_path, sizeof(new_agent_path), "%s%s", new_rootfs_path, agent_path);
	debugf("New agent path: %s", new_agent_path);

	// FIXME:
	/* int ret = 0; */
	/* int src_fd = open(agent_path, O_RDONLY); */
	/* if (src_fd < 0) { */
	/* 	errorf("Could not open %s: %s", agent_path, strerror(errno)); */
	/* 	return -1; */
	/* } */
	/* int dest_fd = open(new_agent_path, O_WRONLY | O_CREAT | O_TRUNC); */
	/* if (dest_fd < 0) { */
	/* 	close(src_fd); */
	/* 	errorf("Could not open %s: %s", new_agent_path, strerror(errno)); */
	/* 	return -1; */
	/* } */
	/* char buffer[4096]; */
	/* while((ret = read(src_fd, buffer, sizeof(buffer))) > 0) { */
	/* 	if (write(dest_fd, buffer, ret) != ret) { */
	/* 		errorf("Could not copy %s in %s: %s", agent_path, */
	/* 			   new_agent_path, strerror(errno)); */
	/* 		close(src_fd); */
	/* 		close(dest_fd); */
	/* 		return -1; */
	/* 	} */
	/* } */
	/* close(src_fd); */
	/* close(dest_fd); */

	/* debugf("Hardlink"); */
	/* if (link(agent_path, new_agent_path) == -1) { */
	/* 	errorf("link(): %s", strerror(errno)); */
	/* } */

	/* debugf("Bind mount"); */
	/* close(open(new_agent_path, O_CREAT | O_TRUNC)); */
	/* if (mount(agent_path, new_agent_path, NULL, MS_BIND, NULL) == -1) { */
	/* 	errorf("mount(): %s", strerror(errno)); */
	/* } */

	strncpy(rootfs_path, new_rootfs_path, size);

	return 0;
}

static int mount_sys_filesystems(void) {
	int i;

   struct sys_fs mounts[] = {
	   { "proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC },
	   { "sys", "/sys", "sysfs", MS_NOSUID | MS_NODEV | MS_NOEXEC },
	   { "dev", "/dev", "devtmpfs", MS_NOSUID },
	   { "tmpfs", "/dev/shm", "tmpfs", MS_NOSUID | MS_NODEV },
	   { "devpts", "/dev/pts", "devpts", MS_NOSUID | MS_NOEXEC },
	   { "tmpfs", "/run", "tmpfs", MS_NOSUID | MS_NODEV },
	   { "tmpfs", "/tmp", "tmpfs", MS_NOSUID | MS_NODEV },
   };

   for (i=0; i < (int)(sizeof(mounts) / sizeof(struct sys_fs)); i++) {
	   const struct sys_fs* m = &mounts[i];
	   debugf("Mounting %s at %s, type %s", m->src, m->dest, m->fs_type);
	   if (mount(m->src, m->dest, m->fs_type, m->flags, NULL) != 0) {
		   errorf("Could not mount sys fs %s: %s", m->src, strerror(errno));
		   return -1;
	   }
   }

   return 0;
}

static int pivot_root(void) {
	char rootfs_path[PATH_MAX] = { 0 };
	char old_rootfs_path[PATH_MAX] = { 0 };

	// Create a new empty rootfs
	if (new_rootfs(rootfs_path, sizeof(rootfs_path)) != 0) {
		errorf("Failed to set up the new root filesystem");
		return -1;
	}

	// bind mount the new rootfs.
	debugf("Bind mounting the new rootfs: %s", rootfs_path);
	if (mount(rootfs_path, rootfs_path, NULL, MS_REC|MS_BIND, NULL) == -1) {
		errorf("Could not bind mount the new rootfs: %s", strerror(errno));
		return -1;
	}

	snprintf(old_rootfs_path, sizeof(old_rootfs_path), "%s/%s",
			 rootfs_path, old_rootfs_dir);
	debugf("Using pivot_root syscall");
	if (syscall(SYS_pivot_root, rootfs_path, old_rootfs_path) < 0) {
		errorf("Could not pivot_root: %s", strerror(errno));
		return -1;
	}

	if (chdir("/") != 0) {
		errorf("Could not change the working directory to /: %s", strerror(errno));
		return -1;
	}

	/* if (mount("/", "/rootfs", NULL, MS_BIND | MS_REC, NULL) != 0) { */
	/* 	// FIXME: */
	/* 	errorf("mount() /: %s", strerror(errno)); */
	/* } */

	// make the old rootfs invisible for all the processes.
	debugf("Unmounting old rootfs");
	if (umount2(old_rootfs_dir, MNT_DETACH) != 0) {
		// It's not fatal
		errorf("Could not umount the old rootfs: %s", strerror(errno));
	}

	// FIXME: remove?
	if (getpid() == 1) {
		// proc, sys and tmp filesystems will be mounted in the Go init() function
		debugf("Filesystems shall be mounted in Go int()");
		return 0;
	}

	debugf("Mounting sys filesystems");
	if (mount_sys_filesystems() != 0) {
		errorf("Failed to mount the filesystems");
		return -1;
	}

	return 0;
}

void c_init(void) {
	// FIXME: spawn bash before join namespace
	const struct namespace* ns = NULL;
	int unshare_flags = 0;
	char rootfs_path[PATH_MAX] = { 0 };

	// FIXME: implement
	/* parse_kernel_cmdline(); */

	if (getenv("_LIBCONTAINER_INITPIPE") != NULL) {
		return;
	}

	// FIMXE: remove
	char cmd[4096] = {0};
	snprintf(cmd, sizeof(cmd), "ls -l /proc/%d/", getpid());
	system(cmd);

	// check supported namespaces
	for (ns = supported_namespaces; ns->name != NULL; ns++) {
		// FIXME: check if the kernel supports it
		debugf("Add namespace %s to unshare flags", ns->name);
		unshare_flags |= ns->type;
	}

	debugf("Unsharing namespaces");
	if (unshare(unshare_flags) == -1) {
		errorf("Could not unshare namespaces %d: %s",
			   unshare_flags, strerror(errno));
		return;
	}

	// run namespace hooks
	for (ns = supported_namespaces; ns->name != NULL; ns++) {
		if (ns->hook != NULL) {
			debugf("Running %s hook", ns->name);
			ns->hook();
		}
	}

	debugf("Running pivot_root");
	if (pivot_root() != 0) {
		errorf("Failed to pivot_root to the new rootfs: %s", rootfs_path);
		return;
	}

	if (fork() != 0) {
		exit(0);
	}
}
