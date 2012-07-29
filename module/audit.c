/* Copyright (C) 2008 Matteo Michelini <matteo.michelini@gmail.com>
 * 		This program is free  software,  you  can redistribuite it
 *		and/or modify it under the terms of the GNU General Public 
 *		License as published by the Free Software Foundation,
 *		Version 2.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/cdev.h>

#include "audit.h"

#define AUTHOR 		"Matteo Michelini <matteo.michelini@gmail.com>"
#define DESCRIPTION	"Linux OpenBSM Kernel Module"

static int audit_open(struct inode *, struct file *);
static int audit_release(struct inode *,struct file *);
static ssize_t audit_read(struct file *flip, char __user *buf, size_t count,
			loff_t *f_pos);

#define DEVICE_NAME	"audit"

int audit_major=AUDIT_MAJOR;
int audit_minor=AUDIT_MINOR;
int static audit_nr_devs=AUDIT_NR_DEVS;

static struct cdev *audit_dev;

/* Device file operation struct */
static struct file_operations audit_fops = {
	.owner	=	THIS_MODULE,
	.read	=	audit_read,
/* ##	.ioctl	=	audit_ioctl, */
	.open	=	audit_open,
	.release=	audit_release
};

static int audit_open(struct inode *inode, struct file *flip)
{
	return 0;
}

static int audit_release(struct inode *inode,struct file *flip)
{
	return 0;
}

static ssize_t audit_read(struct file *flip, char __user *buf, size_t count,
		loff_t *f_pos)
{
	ssize_t ret=0;
	return ret;
}

static int __init init_audit(void)
{
	int dev, result;
	if(audit_major){
		dev=MKDEV(audit_major,audit_minor);
		result=register_chrdev_region(dev,audit_nr_devs,DEVICE_NAME);
	}else{
		result=alloc_chrdev_region(&dev,audit_minor,audit_nr_devs,
		DEVICE_NAME);
		audit_major=MAJOR(dev);
	}
	if(result<0){
		printk(KERN_WARNING "audit: can't get major %d\n",audit_major);
		return result;
	}
	//cdev_init(audit_dev,&audit_fops);
	audit_dev=cdev_alloc();
	audit_dev->ops=&audit_fops;
	cdev_add(audit_dev,dev,audit_nr_devs);
	return 0;
}

/* 
 * can we use __exit ?
 */

static void __exit exit_audit(void)
{
	cdev_del(audit_dev);
	unregister_chrdev_region(audit_major,audit_nr_devs);
	printk(KERN_INFO "Device unloaded successfully\n");
}

module_init(init_audit);
module_exit(exit_audit);
MODULE_SUPPORTED_DEVICE("audit"); /* /dev/audit support */
MODULE_LICENSE("GPL");
MODULE_AUTHOR(AUTHOR);
MODULE_DESCRIPTION(DESCRIPTION);
