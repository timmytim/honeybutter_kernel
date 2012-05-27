/*
 * seandroid_lime.c
 *
 * SEAndroid LIME:
 * Security Enhanced Android
 *   Light-weight Integrity measurement and Mandatory access control subsystem
 *   for Embedded devices
 *
 * Jun Kanai <jun4.kanai@toshiba.co.jp>
 * Ryuichi Koike <ryuichi.koike@toshiba.co.jp>
 *
 * based on root_plug.c
 * Copyright (C) 2002 Greg Kroah-Hartman <greg@kroah.com>
 *
 * _xx_is_valid(), _xx_encode(), _xx_realpath_from_path()
 * is ported from security/tomoyo/realpath.c in linux-2.6.32
 *
 * calc_hmac() is ported from drivers/staging/p9auth/p9auth.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
*/

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/security.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/fs_struct.h>
#include <linux/mount.h>
#include <linux/mnt_namespace.h>
#include <linux/ptrace.h>
#include <linux/magic.h>
#include <linux/version.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/kobject.h>
#include <linux/genhd.h>
#include <linux/kobj_map.h>

/* This module deals with struct bus_type_private in order to get kernel internal  */
/* bus information.  In common usage, the struct is private. Therefore we include a header  */
/* file from a abnormal path. */
#include "../drivers/base/base.h"

/* another internal header for vfsmount_lock. */
#include <../fs/internal.h>

#ifdef CONFIG_SECURITY_SEALIME_DEBUGPRINT
#define PRINTK printk
#else
#define PRINTK(arg, ...)
#endif

#define CONFIG_SECURITY_SEALIME_HASH_ALGORITHM "sha1"
#define TOSLSM_DIGEST_SIZE 20

//#define HOOKNAME_PTRACE_ACCESS_CHECK	/* 2.6.32 */
//#define SEALIME_UNLOADABLE

extern struct kset *bus_kset;

struct security_operations *lkm_secops = NULL;

static inline bool _xx_is_valid(const unsigned char c)
{
	return c > ' ' && c < 127;
}

static int _xx_encode(char *buffer, int buflen, const char *str)
{
	while (1) {
		const unsigned char c = *(unsigned char *)str++;

		if (_xx_is_valid(c)) {
			if (--buflen <= 0)
				break;
			*buffer++ = (char)c;
			if (c != '\\')
				continue;
			if (--buflen <= 0)
				break;
			*buffer++ = (char)c;
			continue;
		}
		if (!c) {
			if (--buflen <= 0)
				break;
			*buffer = '\0';
			return 0;
		}
		buflen -= 4;
		if (buflen <= 0)
			break;
		*buffer++ = '\\';
		*buffer++ = (c >> 6) + '0';
		*buffer++ = ((c >> 3) & 7) + '0';
		*buffer++ = (c & 7) + '0';
	}
	return -ENOMEM;
}

//#ifdef CONFIG_SECURITY_SEALIME_NATIVE_HONEYCOMB_SUPPORT //obsolete
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36)
int _xx_realpath_from_path(struct path *path, char *newname,
                           int newname_len)
{
	int error = -ENOMEM;
	struct dentry *dentry = path->dentry;
	char *sp;

	if (!dentry || !path->mnt || !newname || newname_len <= 2048)
		return -EINVAL;
	if (dentry->d_op && dentry->d_op->d_dname) {
		/* For "socket:[\$]" and "pipe:[\$]". */
		static const int offset = 1536;
		sp = dentry->d_op->d_dname(dentry, newname + offset,
		                           newname_len - offset);
	} else {
		struct path ns_root = {.mnt = NULL, .dentry = NULL};

		spin_lock(&dcache_lock);
		/* go to whatever namespace root we are under */
		sp = __d_path(path, &ns_root, newname, newname_len);
		spin_unlock(&dcache_lock);
		/* Prepend "/proc" prefix if using internal proc vfs mount. */
		if (!IS_ERR(sp) && (path->mnt->mnt_flags & MNT_INTERNAL) &&
		    (path->mnt->mnt_sb->s_magic == PROC_SUPER_MAGIC)) {
			sp -= 5;
			if (sp >= newname)
				memcpy(sp, "/proc", 5);
			else

	sp = ERR_PTR(-ENOMEM);
		}
	}
	if (IS_ERR(sp))
		error = PTR_ERR(sp);
	else
		error = _xx_encode(newname, sp - newname, sp);
	/* Append trailing '/' if dentry is a directory. */
	if (!error && dentry->d_inode && S_ISDIR(dentry->d_inode->i_mode)
	    && *newname) {
		sp = newname + strlen(newname);
		if (*(sp - 1) != '/') {
			if (sp < newname + newname_len - 4) {
				*sp++ = '/';
				*sp = '\0';
			} else {
				error = -ENOMEM;
			}
		}
	}
	return error;
}
#else
static int _xx_realpath_from_path(struct path *path, char *newname,
				  int newname_len)
{
	struct dentry *dentry = path->dentry;
	int error = -ENOMEM;
	char *sp;

	if (!dentry || !path->mnt || !newname || newname_len <= 2048)
		return -EINVAL;
	if (dentry->d_op && dentry->d_op->d_dname) {
		/* For "socket:[\$]" and "pipe:[\$]". */
		static const int offset = 1536;
		sp = dentry->d_op->d_dname(dentry, newname + offset,
					   newname_len - offset);
	} else {
		/* Taken from d_namespace_path(). */
		struct path ns_root = { };
		struct path root;
		struct path tmp;

		read_lock(&current->fs->lock);
		root = current->fs->root;
		path_get(&root);
		read_unlock(&current->fs->lock);
		spin_lock(&vfsmount_lock);
		if (root.mnt && root.mnt->mnt_ns)
			ns_root.mnt = mntget(root.mnt->mnt_ns->root);
		if (ns_root.mnt)
			ns_root.dentry = dget(ns_root.mnt->mnt_root);
		spin_unlock(&vfsmount_lock);
		spin_lock(&dcache_lock);
		tmp = ns_root;
		sp = __d_path(path, &tmp, newname, newname_len);
		spin_unlock(&dcache_lock);
		path_put(&root);
		path_put(&ns_root);
	}
	if (IS_ERR(sp)) {
		error = PTR_ERR(sp);
	} else {
		error = _xx_encode(newname, sp - newname, sp);
	}
#if 1
	/* Append trailing '/' if dentry is a directory. */
	if (!error && dentry->d_inode && S_ISDIR(dentry->d_inode->i_mode)
	    && *newname) {
		sp = newname + strlen(newname);
		if (*(sp - 1) != '/') {
			if (sp < newname + newname_len - 4) {
				*sp++ = '/';
				*sp = '\0';
			} else {
				error = -ENOMEM;
			}
		}
	}
#endif
	return error;
}
#endif /* 2.6.36 or later support */
EXPORT_SYMBOL(_xx_realpath_from_path);

static char *calc_hmac(char *plain_text, unsigned int plain_text_size,
		      char *key, unsigned int key_size)
{
	struct scatterlist sg;
	char *result;
	struct crypto_hash *tfm;
	struct hash_desc desc;
	int ret;

	tfm = crypto_alloc_hash("hmac(sha1)", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(tfm)) {
		PRINTK(KERN_ERR
		       "failed to load transform for hmac(sha1): %ld\n",
		       PTR_ERR(tfm));
		return NULL;
	}

	desc.tfm = tfm;
	desc.flags = 0;

	result = kzalloc(TOSLSM_DIGEST_SIZE, GFP_KERNEL);
	if (!result) {
		PRINTK(KERN_ERR "out of memory!\n");
		goto out;
	}

	sg_set_buf(&sg, plain_text, plain_text_size);

	ret = crypto_hash_setkey(tfm, key, key_size);
	if (ret) {
		PRINTK(KERN_ERR "setkey() failed ret=%d\n", ret);
		kfree(result);
		result = NULL;
		goto out;
	}

	ret = crypto_hash_digest(&desc, &sg, plain_text_size, result);
	if (ret) {
		PRINTK(KERN_ERR "digest() failed ret=%d\n", ret);
		kfree(result);
		result = NULL;
		goto out;
	}

out:
	crypto_free_hash(tfm);
	return result;
}
EXPORT_SYMBOL(calc_hmac);

/* device dependent ? */
#define DEVICE_TYPE "usb_device"
#define DEVICE_DRIVER_NAME "usb"

enum inter_bus {USB, MMC, NONE};

enum req_stat {
	SEARCH_MN_NUM,
	SEARCH_MN_FOUND,
	SEARCH_USB_DESCRIPTOR,
	SEARCH_FOUND,
};

struct device_search_request {
	int major;
	int minor;
	enum req_stat stat;
	enum inter_bus bus;
	struct device *dev;
};

struct device_search_response {
	enum inter_bus bus;
	struct device *dev;
};

#define to_bus(obj) container_of(obj, struct bus_type_private, subsys.kobj)

static int is_usb_device_root(struct device *dev)
{
	if(!dev->driver) return 0;
	if(!dev->type)   return 0;


	if((!strcmp(dev->type->name, DEVICE_TYPE)) &&
		(!strcmp(dev->driver->name, DEVICE_DRIVER_NAME))) {
		return 1;
	}
	return 0;
}

static int match_mn_num(struct device *dev, void *data)
{
	struct device_search_request *req = (struct device_search_request *)data;

	if(req->bus == NONE) {
		 return 0;
	}

	if(req->stat == SEARCH_FOUND) {
		return 0;
	}

	if(req->stat == SEARCH_MN_NUM) {
		if( (req->major == MAJOR(dev->devt)) && (req->minor == MINOR(dev->devt)) ) {
			req->dev = dev;
			if(req->bus == USB) {req->stat = SEARCH_USB_DESCRIPTOR; }
			if(req->bus == MMC) {req->stat = SEARCH_FOUND;}
		}
	}

	device_for_each_child(dev, data, match_mn_num);

	if(req->stat == SEARCH_USB_DESCRIPTOR && is_usb_device_root(dev)) {
		req->dev = dev;
		req->stat = SEARCH_FOUND;
	}

	return 0;
}

/* search device by using major number no and minor no  */
static int device_find_mn_num(struct device_search_request *req, struct device_search_response *res)
{
	struct list_head *p;

	kset_get(bus_kset);
	list_for_each(p, &(bus_kset->list)) {
		struct kobject *bus_kobj = container_of(p, struct kobject, entry);
		struct bus_type_private *pbus = to_bus(bus_kobj);

		req->stat = SEARCH_MN_NUM;
		req->bus = NONE;

		/* printk("[BUS]=%s\n", bus_kobj->name); */
		if(!strcmp(bus_kobj->name, "usb")) {
			req->bus = USB;
		} else if(!strcmp(bus_kobj->name, "mmc")) {
			req->bus = MMC;
		} else {
			req->bus = NONE;
		}

		bus_for_each_dev(pbus->bus, NULL, req, match_mn_num);

		if(req->stat == SEARCH_FOUND) {
			res->bus = req->bus;
			res->dev = req->dev;
			return 1;		/* found */
		}
	}
	kset_put(bus_kset);
	return 0;					/* not found */
}
EXPORT_SYMBOL(device_find_mn_num);

static int sealime_ptrace_access_check(struct task_struct *child,
				       unsigned int mode)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32)
//#ifdef CONFIG_SECURITY_SEALIME_HOOKNAME_PTRACE_ACCESS_CHECK //obsolete
	if (lkm_secops) return lkm_secops->ptrace_access_check(child, mode);
#else
	if (lkm_secops) return lkm_secops->ptrace_may_access(child, mode);
#endif
	return 0;
}

static int sealime_ptrace_traceme(struct task_struct *parent)
{
	if (lkm_secops) return lkm_secops->ptrace_traceme(parent);
	return 0;
}

static int sealime_sb_mount(char *dev_name, struct path *path,
			    char *type, unsigned long flags, void *data)
{
	if (lkm_secops) return lkm_secops->sb_mount(dev_name, path, type, flags, data);
	return 0;
}

static int sealime_sb_umount(struct vfsmount *mnt, int flags)
{
	return 0;
}

static int sealime_sb_pivotroot(struct path *old_path, struct path *new_path)
{
	if (lkm_secops) return lkm_secops->sb_pivotroot(old_path, new_path);
	return 0;
}

static int sealime_path_chroot(struct path *path)
{
	if (lkm_secops) return lkm_secops->path_chroot(path);
	return 0;
}

static int sealime_file_permission(struct file *file, int mask)
{
	if (lkm_secops) return lkm_secops->file_permission(file, mask);
	return 0;
}

static int sealime_bprm_secureexec(struct linux_binprm *bprm)
{
	if (lkm_secops) return lkm_secops->bprm_secureexec(bprm);
	return 0;
}

static int sealime_path_mknod(struct path *path, struct dentry *dentry,
			      int mode, unsigned int dev)
{
	if (lkm_secops) return lkm_secops->path_mknod(path, dentry, mode, dev);
	return 0;
}

static int sealime_path_unlink(struct path *path, struct dentry *dentry)
{
	if (lkm_secops) return lkm_secops->path_unlink(path, dentry);
	return 0;
}

static int sealime_path_rename(struct path *old_dir, struct dentry *old_dentry,
			       struct path *new_dir, struct dentry *new_dentry)
{
	if (lkm_secops) return lkm_secops->path_rename(old_dir, old_dentry, new_dir, new_dentry);
	return 0;
}

static int sealime_task_create(unsigned long clone_flags)
{
	if (lkm_secops) return lkm_secops->task_create(clone_flags);
	return 0;
}

static int sealime_init_module(const char *image, unsigned long len)
{
	if (lkm_secops) return lkm_secops->init_module(image, len);
	return 0;
}

static int sealime_task_prctl(int option, unsigned long arg2,
			      unsigned long arg3, unsigned long arg4,
			      unsigned long arg5)
{

	if (lkm_secops) return lkm_secops->task_prctl(option, arg2, arg3, arg4, arg5);
	return cap_task_prctl(option, arg2, arg3, arg3, arg5);
}

static int sealime_dentry_open(struct file *file, const struct cred *cred)
{
	if (lkm_secops) return lkm_secops->dentry_open(file, cred);
	return 0;
}

static int sealime_path_mkdir(struct path *dir, struct dentry *dentry, int mode)
{
	if (lkm_secops) return lkm_secops->path_mkdir(dir, dentry, mode);
	return 0;
}

static int sealime_file_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	if (lkm_secops) return lkm_secops->file_ioctl(file, cmd, arg);
	return 0;
}

static int sealime_socket_connect (struct socket *sock,
                                   struct sockaddr *address, int addrlen)
{
  if (lkm_secops) return lkm_secops->socket_connect(sock, address, addrlen);
  return 0;
}

static int sealime_socket_listen (struct socket *sock, int backlog)
{
	 if (lkm_secops) return lkm_secops->socket_listen(sock, backlog);
	 return 0;
}

static struct security_operations sealime_security_ops = {
#ifndef CONFIG_SECURITY_SEALIME_HOOKNAME_PTRACE_ACCESS_CHECK
	.ptrace_may_access = sealime_ptrace_access_check,
#else
	.ptrace_access_check = sealime_ptrace_access_check,
#endif
	.ptrace_traceme = sealime_ptrace_traceme,
	.sb_mount = sealime_sb_mount,
	.sb_umount = sealime_sb_umount,
	.sb_pivotroot = sealime_sb_pivotroot,
	.file_permission = sealime_file_permission,
	.bprm_secureexec = sealime_bprm_secureexec,
	.path_mknod = sealime_path_mknod,
	.path_unlink = sealime_path_unlink,
	.path_rename = sealime_path_rename,
	.task_create = sealime_task_create,
	.path_chroot = sealime_path_chroot,
	.task_prctl = sealime_task_prctl,
	.dentry_open = sealime_dentry_open,
	.init_module = sealime_init_module,
	.path_mkdir = sealime_path_mkdir,
	.file_ioctl = sealime_file_ioctl,
	.socket_connect = sealime_socket_connect,
	.socket_listen = sealime_socket_listen,

};

static int __init sealime_init(void)
{
	if (register_security(&sealime_security_ops)) {
		PRINTK(KERN_INFO "[SEAndroid_Lime] Failure registering LSM\n");
		return -EINVAL;
	}
	PRINTK(KERN_INFO "[SEAndroid_Lime] LSM module initialized\n");

	return 0;
}

static int register_sealime(struct security_operations *sec_ops) {
#ifndef SEALIME_UNLOADABLE
	if (lkm_secops == NULL) {
#endif
		lkm_secops = sec_ops;
		PRINTK(KERN_INFO "[SEAndroid_LIME] allow: Sealime LKM is registered!\n");
#ifndef SEALIME_UNLOADABLE
	} else {
		PRINTK(KERN_INFO "[SEAndroid_LIME] reject: Sealime LKM is already registered!\n");
	}
#endif
	return 0;
}
EXPORT_SYMBOL(register_sealime);
EXPORT_SYMBOL(__ptrace_unlink);
EXPORT_SYMBOL(cap_task_prctl);

security_initcall(sealime_init);
