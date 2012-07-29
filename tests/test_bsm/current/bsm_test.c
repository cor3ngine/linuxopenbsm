/* Copyright (C) 2008 Matteo Michelini <matteo.michelini@gmail.com>
 *              This program is free  software,  you  can redistribuite it
 *              and/or modify it under the terms of the GNU General Public 
 *              License as published by the Free Software Foundation,
 *              Version 2.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <net/sock.h>
#include <net/netlink.h>
#include <linux/kthread.h>
#include <linux/time.h>

#include "audit.h"
#include "audit_internal.h"
#include "audit_record.h"

/* FIXME: this is a userspace header file it is here only
 * for kernel space test
 */
#include "audit_userspace.h"

#define AUDIT_BUFSIZE 1024

#define GET_TOKEN_AREA(t, dptr, length) do {			\
	t = kmalloc(sizeof(struct au_token), GFP_KERNEL);	\
	t->t_data = kmalloc(length, GFP_KERNEL);		\
	t->len = length;					\
	dptr = t->t_data;					\
}while(0)

/*#############################################
 * OK THIS IS WORKING FINE
 * ############################################
 * Aug 21 2008: added kau_open()
 * Aug 21 2008: added kau_write()
 * Aug 21 2008: added basic kau_close() without header and trailer
 * Aug 21 2008: implementing the queue of BSM tokens 
 * Aug 22 2008: added netlink_receive()
 * Aug 22 2008: added netlink_send()
 * Aug 25 2008: added ksend_thread() added locking sync
 * Aug 26 2008: added au_to_header32_tm()
 * Aug 26 2008: added au_to_return32()
 * Aug 26 2008: added au_to_subject32()
 * Aug 26 2008: added au_to_trailer()
 * Aug 26 2008: added header and trailer support for kau_close()
 */

static struct au_record *kau_open(void);
static void kau_write(struct au_record *rec, struct au_token *tok);
static void kau_close(struct au_record *rec, struct timespec *ctime, short event);

struct au_token *au_to_header32_tm(int rec_size, au_event_t e_type, au_emod_t e_mod,
	struct timeval tm);
struct au_token *au_to_return32(char status, u_int32_t ret);
struct au_token *au_to_subject32(uid_t auid, uid_t euid, gid_t egid, uid_t ruid,
		gid_t rgid, pid_t pid, unsigned int sessionid, au_tid_t *tid);
static struct au_token *au_to_trailer(int rec_size); 

struct audit_buffer *audit_buffer_alloc(int len, gfp_t gfp_mask);

static void audit_log_format_bsm(struct audit_buffer *ab_bsm, struct au_record *rec);

void netlink_receive(struct sk_buff *skb);
void netlink_send(struct audit_buffer *ab_bsm);

/* only for testing */
//void output(struct audit_buffer *ab_bsm);

struct audit_buffer {
	struct list_head 	list;
	struct sk_buff		*skb; 
	//struct audit_context	*ctx;
	gfp_t			gfp_mask;
};

/* for thread sync */
static struct task_struct *ksend_task;
static DECLARE_WAIT_QUEUE_HEAD(ksend_wait);
/* netlink socket */
struct sock *nl_sk;
/* userspace daemon pid */
int nlk_pid = 0;

/* this works just once for many operation
 * we must iterate kthread_run but we have to
 * implement a global variable of au_record queues
 * and manage a double wake_up variable like
 * kernel/audit.c
 */
static int ksend_thread(void *arg)
{
	struct audit_buffer *ab_bsm = (struct audit_buffer *)arg;

	DECLARE_WAITQUEUE(wait, current);
	set_current_state(TASK_INTERRUPTIBLE);
	add_wait_queue(&ksend_wait, &wait);
	if(!nlk_pid)
	{
		schedule();
	}
	__set_current_state(TASK_RUNNING);
	remove_wait_queue(&ksend_wait, &wait);
	netlink_send(ab_bsm);
	return 0;
}

void netlink_receive(struct sk_buff *skb)
{
	struct nlmsghdr *nlh;
	
	nlh = (struct nlmsghdr *)skb->data;
	printk(KERN_ALERT "%s\n", (char *)NLMSG_DATA(nlh));
	nlk_pid = NETLINK_CB(skb).pid;
	printk(KERN_ALERT "nlk_pid: %d\n", nlk_pid);
	wake_up_interruptible(&ksend_wait);
}

void netlink_send(struct audit_buffer *ab_bsm)
{
	struct sk_buff *skb = ab_bsm->skb;
	struct nlmsghdr *nlh = nlmsg_hdr(skb);

	nlh->nlmsg_len = skb->len - NLMSG_SPACE(0);
	netlink_unicast(nl_sk, skb, nlk_pid, 0);
}

static int __init bsm_test_init(void)
{

	struct audit_buffer *ab_bsm;
	struct au_token *t;
	struct au_record *rec;
	au_tid_t tid;

	/* only for testing */
	uid_t auid = 10;
	uid_t euid = 0;
	gid_t egid = 1;
	uid_t ruid = 2;
	gid_t rgid = 3;
	pid_t pid = 4;
	unsigned int sessionid = 5;
	char status = '0';
	u_int32_t ret = 12;
	short event = 22;
	struct timespec *ctime = kmalloc(sizeof(*ctime), GFP_KERNEL);
	*ctime = CURRENT_TIME;
	//char *tty = NULL;
	/* ---------------- */

	printk(KERN_ALERT "bsm_test is starting\n");
	nl_sk = netlink_kernel_create(&init_net, NETLINK_UNUSED, 0,
			netlink_receive, NULL, THIS_MODULE);
	if(!nl_sk)
		printk(KERN_ALERT "Error while initilizing netlink"
				" socket\n");
	rec = kau_open();
	
	/* FIXME: we have to add the token... */
	memset(&tid, 0,  sizeof(tid));
	t = au_to_subject32(auid, euid, egid, ruid, rgid, pid, sessionid, &tid);
	kau_write(rec, t);
	/* FIXME: fix au_to_retur32 */
	t = au_to_return32(status, ret);
	kau_write(rec, t);
	/* FIXME: fix kau_close as the prototype */
	kau_close(rec, ctime, event);
	ab_bsm = audit_buffer_alloc(rec->len + AUDIT_HEADER_SIZE + AUDIT_TRAILER_SIZE, GFP_KERNEL);
	audit_log_format_bsm(ab_bsm, rec);
	ksend_task = kthread_run(ksend_thread, ab_bsm, "ksend");

	/* only for testing */
//	output(ab_bsm);
	return 0;
}

struct au_token *au_to_header32_tm(int rec_size, au_event_t e_type, au_emod_t e_mod,
	struct timeval tm)
{
	struct au_token *t;
	u_char *dptr = NULL;
	u_int32_t timems;

	GET_TOKEN_AREA(t, dptr, sizeof(u_char) + sizeof(u_int32_t) +
		sizeof(u_char) + 2 * sizeof(u_int16_t) + 2 * sizeof(u_int32_t));

	ADD_U_CHAR(dptr, AUT_HEADER32);
	ADD_U_INT32(dptr, rec_size);
	ADD_U_CHAR(dptr, AUDIT_HEADER_VERSION_OPENBSM);
	ADD_U_INT16(dptr, e_type);
	ADD_U_INT16(dptr, e_mod);

	timems = tm.tv_usec/1000;
	ADD_U_INT32(dptr, tm.tv_sec);
	ADD_U_INT32(dptr, timems);
	return t;
}

struct au_token *au_to_subject32(uid_t auid, uid_t euid, gid_t egid, uid_t ruid,
		gid_t rgid, pid_t pid, unsigned int sessionid, au_tid_t *tid)
{
	struct au_token *t;
	u_char *dptr = NULL;

	GET_TOKEN_AREA(t, dptr, sizeof(u_char) + 9 * sizeof(u_int32_t));

	ADD_U_CHAR(dptr, AUT_SUBJECT32);
	ADD_U_INT32(dptr, auid);
	ADD_U_INT32(dptr, euid);
	ADD_U_INT32(dptr, egid);
	ADD_U_INT32(dptr, ruid);
	ADD_U_INT32(dptr, rgid);
	ADD_U_INT32(dptr, pid);
	ADD_U_INT32(dptr, sessionid);
	ADD_U_INT32(dptr, tid->port);
	ADD_MEM(dptr, &tid->machine, sizeof(u_int32_t));
	return t;
}

struct au_token *au_to_return32(char status, u_int32_t ret)
{
	struct au_token *t;
	u_char *dptr = NULL;

	GET_TOKEN_AREA(t, dptr, 2 * sizeof(u_char) + sizeof(u_int32_t));

	ADD_U_CHAR(dptr, AUT_RETURN32);
	ADD_U_CHAR(dptr, status);
	ADD_U_INT32(dptr, ret);
	return t;
}

static struct au_token *au_to_trailer(int rec_size)
{
	struct au_token *t;
	u_char *dptr = NULL;
	u_int16_t magic = TRAILER_PAD_MAGIC;

	GET_TOKEN_AREA(t, dptr, sizeof(u_char) + sizeof(u_int16_t) +
		sizeof(u_int32_t));

	ADD_U_CHAR(dptr, AUT_TRAILER);
	ADD_U_INT16(dptr, magic);
	ADD_U_INT32(dptr, rec_size);
	return t;
}

/* initialize au_record and the au_token list embedded into
 * au_record
 */
static struct au_record *kau_open(void)
{
	struct au_record *rec;
	struct au_token *t_list;

	rec = kmalloc(sizeof(*rec), GFP_KERNEL);
	rec->data = NULL;
	t_list = &(rec->token_q);
	INIT_LIST_HEAD(&(t_list->list));
	rec->len = 0;
	rec->used = 1;
	return rec;
}

/* add the token to au_token list embedded into au_record */
static void kau_write(struct au_record *rec, struct au_token *tok)
{
	struct au_token *t_list;

	t_list = &(rec->token_q);
	list_add_tail(&(tok->list), &(t_list->list));
	rec->len += tok->len;
}

static void kau_close(struct au_record *rec, struct timespec *ctime, short event)
{
	u_char *dptr;
	struct list_head *pos, *q;
	size_t tot_rec_size;
	struct au_token *t, *t_list, *trail, *hdr;
 	struct timeval tm;

	tot_rec_size = rec->len + AUDIT_HEADER_SIZE + AUDIT_TRAILER_SIZE;
	printk(KERN_ALERT "tot_rec_size: %d\n", tot_rec_size);
	rec->data = kmalloc(tot_rec_size, GFP_KERNEL); 
	
	tm.tv_usec = ctime->tv_nsec / 1000;
	tm.tv_sec = ctime->tv_sec;
	hdr = au_to_header32_tm(tot_rec_size, event, 0, tm);
	trail = au_to_trailer(tot_rec_size);
	
	/* serialize the au_token list into rec->data */
	dptr = rec->data;
	t_list = &(rec->token_q);
	/* adding the header token to the list */
	list_add(&(hdr->list), &(t_list->list));
	/* adding the trailer token to the list */
	list_add_tail(&(trail->list), &(t_list->list));
	
	list_for_each_safe(pos, q, &(t_list->list))
	{
		t = list_entry(pos, struct au_token, list);
		memcpy(dptr, t->t_data, t->len);
		dptr += t->len;
		list_del(pos);
		kfree(t);
	}
}

struct audit_buffer *audit_buffer_alloc(int len, gfp_t gfp_mask)
{
	struct audit_buffer *ab_bsm = NULL;
	struct nlmsghdr *nlh;

	ab_bsm = kmalloc(sizeof(*ab_bsm), gfp_mask);
	if (!ab_bsm)
		goto error;
	ab_bsm->skb = alloc_skb(len, gfp_mask);
	if (!ab_bsm->skb)
		goto error;
	ab_bsm->gfp_mask = gfp_mask;
	nlh = (struct nlmsghdr *)skb_put(ab_bsm->skb, NLMSG_SPACE(0));
	/* FIXME: we have to introduce type maybe we can use 
	 * BSM_TRAIL
	 */
	//nlh->nlmsg_type = type;
	nlh->nlmsg_flags = 0;
	nlh->nlmsg_pid = 0;
	nlh->nlmsg_seq = 0;
	return ab_bsm;
	error:
		kfree(ab_bsm);
		return NULL;
}

static void audit_log_format_bsm(struct audit_buffer *ab_bsm, struct au_record *rec)
{
	int avail;
	struct sk_buff *skb;

	if(!ab_bsm)
		return;
	
	skb = ab_bsm->skb;
	avail = skb_tailroom(skb);
	//printk(KERN_ALERT "%d %d\n", avail, t->len);
	
	/* FIXME: maybe we can delete the if because avail is exactly
	 * the size of the audit record
	 */
	if (avail >= rec->len)
	{
		/* we have to copy rec->data to skb for sending 
		 * serialized tokens to userspace
		 */
		memcpy(skb_tail_pointer(skb), rec->data, rec->len + AUDIT_HEADER_SIZE + AUDIT_TRAILER_SIZE);
		skb_put(skb, rec->len + AUDIT_HEADER_SIZE + AUDIT_TRAILER_SIZE);
	}
}
/*
void output(struct audit_buffer *ab_bsm)
{
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	u_char *buf = NULL;
	//int size = sizeof(u_char) + 6 * sizeof(u_int32_t);
	u_char *tok = kmalloc(sizeof(u_char), GFP_KERNEL);
	int err = 0;
	int len = 40;
	int start = 0;

	skb = ab_bsm->skb;
	// now in skb->data we have rec->data 
	nlh = (struct nlmsghdr *)skb->data;
	
	//we must add the functions for managing bsm trails
	memcpy(buf, (char *)NLMSG_DATA(nlh), sizeof(u_char));
	READ_TOKEN_U_CHAR(buf, len, tok, start, err);
	printk(KERN_ALERT "%s\n", tok);
	//printk(KERN_ALERT "%s\n", (char *)NLMSG_DATA(nlh));
	kfree(ab_bsm);
}
*/
static void __exit bsm_test_exit(void)
{
	sock_release(nl_sk->sk_socket);
	printk(KERN_ALERT "bsm_test is exiting\n");
}

module_init(bsm_test_init);
module_exit(bsm_test_exit);
