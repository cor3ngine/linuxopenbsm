#include <linux/init.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <net/sock.h>
#include <net/netlink.h>

#include "audit_internal.h"

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
 * we have to add the netlink send
 * ############################################
 */

struct au_token *au_to_subject32(uid_t euid, gid_t egid, uid_t uid,
		gid_t gid, pid_t pid, unsigned int sessionid, char *tty);

struct audit_buffer *audit_log_start_bsm(gfp_t gfp_mask);

static void audit_log_format_bsm(struct audit_buffer *ab_bsm, struct au_token *t);

/* only for testing */
void output(struct audit_buffer *ab_bsm);

struct audit_buffer {
	struct list_head 	list;
	struct sk_buff		*skb; 
	//struct audit_context	*ctx;
	gfp_t			gfp_mask;
};

static int __init bsm_test_init(void)
{

	struct audit_buffer *ab_bsm;
	struct au_token *t;
	
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
	ab_bsm = audit_log_start_bsm(GFP_KERNEL);
	t = au_to_subject32(euid, egid, uid, gid, pid, sessionid, tty);
	audit_log_format_bsm(ab_bsm, t);
	/* only for testing */
	output(ab_bsm);
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

struct audit_buffer *audit_log_start_bsm(gfp_t gfp_mask)
{
	struct audit_buffer *ab_bsm = NULL;
	struct nlmsghdr *nlh;

	ab_bsm = kmalloc(sizeof(*ab_bsm), gfp_mask);
	if (!ab_bsm)
		goto error;
	ab_bsm->skb = alloc_skb(AUDIT_BUFSIZE, gfp_mask);
	if (!ab_bsm->skb)
		goto error;
	ab_bsm->gfp_mask = gfp_mask;
	nlh = (struct nlmsghdr *)skb_put(ab_bsm->skb, NLMSG_SPACE(0));
	//FIXME: we have to introduce type
	//nlh->nlmsg_type = type;
	nlh->nlmsg_flags = 0;
	nlh->nlmsg_pid = 0;
	nlh->nlmsg_seq = 0;
	return ab_bsm;
	error:
		kfree(ab_bsm);
		return NULL;
}

static void audit_log_format_bsm(struct audit_buffer *ab_bsm, struct au_token *t)
{
	int avail;
	struct sk_buff *skb;

	if(!ab_bsm)
		return;
	
	skb = ab_bsm->skb;
	avail = skb_tailroom(skb);
	//printk(KERN_ALERT "%d %d\n", avail, t->len);
	if (avail >= t->len)
	{
		//memcpy(skb_tail_pointer(skb), t->t_data, t->len);
		//snprintf(skb_tail_pointer(skb), strlen("prova")+1, "prova");
		memcpy(skb_tail_pointer(skb), "prova", strlen("prova")+1);
		skb_put(skb, strlen("prova"));
		memcpy(skb_tail_pointer(skb), " This is a test", strlen(" This is a test")+1);
	}
}

void output(struct audit_buffer *ab_bsm)
{
	struct sk_buff *skb;
	struct nlmsghdr *nlh;

	skb = ab_bsm->skb;
	nlh = (struct nlmsghdr *)skb->data;
	printk(KERN_ALERT "%s\n", (char *)NLMSG_DATA(nlh));
	kfree(ab_bsm);
}

static void __exit bsm_test_exit(void)
{
	printk(KERN_ALERT "bsm_test is exiting\n");
}

module_init(bsm_test_init);
module_exit(bsm_test_exit);
