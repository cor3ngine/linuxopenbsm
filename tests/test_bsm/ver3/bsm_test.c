#include <linux/init.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <net/sock.h>
#include <net/netlink.h>

#include "audit_internal.h"
/* FIXME: this is a userspace header file it is here only
 * for kernel space test
 */
#include "audit_userspace.h"

#define AUDIT_BUFSIZE 1024

#define AUT_SUBJECT32 0x24

#define GET_TOKEN_AREA(t, dptr, length) do {			\
	t = kmalloc(sizeof(struct au_token), GFP_KERNEL);	\
	t->t_data = kmalloc(length, GFP_KERNEL);		\
	t->len = length;					\
	dptr = t->t_data;					\
}while(0)

/*#############################################
 * OK THIS IS WORKING FINE
 * we have to manage locking/threads
 * ############################################
 * Aug 21 2008: added kau_open()
 * Aug 21 2008: added kau_write()
 * Aug 21 2008: added basic kau_close() without header and trailer
 * Aug 21 2008: implementing the queue of BSM tokens 
 * Aug 22 2008: added netlink_receive()
 * Aug 22 2008: added netlink_send()
 */

static struct au_record *kau_open(void);
static void kau_write(struct au_record *rec, struct au_token *tok);
static void kau_close(struct au_record *rec);

struct au_token *au_to_subject32(uid_t euid, gid_t egid, uid_t uid,
		gid_t gid, pid_t pid, unsigned int sessionid, char *tty);

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

/* netlink socket */
struct sock *nl_sk;
/* userspace daemon pid */
int nlk_pid = 0;


void netlink_receive(struct sk_buff *skb)
{
	struct nlmsghdr *nlh;

	nlh = (struct nlmsghdr *)skb->data;
	printk(KERN_ALERT "%s\n", (char *)NLMSG_DATA(nlh));
	nlk_pid = NETLINK_CB(skb).pid;
	printk(KERN_ALERT "nlk_pid: %d\n", nlk_pid);
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
	
	/* only for testing */
	uid_t euid = 0;
	gid_t egid = 1;
	uid_t uid = 2;
	gid_t gid = 3;
	pid_t pid = 4;
	unsigned int sessionid = 5;
	char *tty = NULL;
	/* ---------------- */

	printk(KERN_ALERT "bsm_test is starting\n");
	nl_sk = netlink_kernel_create(&init_net, NETLINK_UNUSED, 0,
			netlink_receive, NULL, THIS_MODULE);
	if(!nl_sk)
		printk(KERN_ALERT "Error while initilizing netlink"
				" socket\n");
	rec = kau_open();
	
	/* FIXME: we have to fill the audit record with header, tokens,
	 * subject, return, trailer
	 */
	t = au_to_subject32(euid, egid, uid, gid, pid, sessionid, tty);
	kau_write(rec, t);
	kau_close(rec);
	ab_bsm = audit_buffer_alloc(rec->len, GFP_KERNEL);
	audit_log_format_bsm(ab_bsm, rec);
	/* FIXME: before netlink_send nlk_pid MUST be != 0
	 * this means that netlink_receive MUST be executed before
	 * proceding with netlink_send()
	 */
//	netlink_send(ab_bsm);
	/* only for testing */
//	output(ab_bsm);
	return 0;
}

struct au_token *au_to_subject32(uid_t euid, gid_t egid, uid_t uid,
		gid_t gid, pid_t pid, unsigned int sessionid, char *tty)
{
	struct au_token *t;
	u_char *dptr = NULL;

	GET_TOKEN_AREA(t, dptr, sizeof(u_char) + 6 * sizeof(u_int32_t));

	ADD_U_CHAR(dptr, AUT_SUBJECT32);
	ADD_U_INT32(dptr, euid);
	ADD_U_INT32(dptr, egid);
	ADD_U_INT32(dptr, uid);
	ADD_U_INT32(dptr, gid);
	ADD_U_INT32(dptr, pid);
	ADD_U_INT32(dptr, sessionid);
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

/* FIXME: kau_close must add header and trailer to the token */
static void kau_close(struct au_record *rec)
{
	u_char *dptr;
	struct list_head *pos, *q;
	struct au_token *t, *t_list;

	/* serialize the au_token list into rec->data */ 
	/* FIXME: after adding HEADER and TRAILER change
	 * rec->len with rec->len + head_len + trail_len
	 */
	rec->data = kmalloc(rec->len, GFP_KERNEL); 
	dptr = rec->data;
	t_list = &(rec->token_q);
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
		memcpy(skb_tail_pointer(skb), rec->data, rec->len);
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
