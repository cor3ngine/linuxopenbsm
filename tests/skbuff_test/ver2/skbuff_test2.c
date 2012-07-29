#include <linux/init.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/netlink.h>

#define BUFSIZE 1024

/**
 * see net/core/skbuff.c and include/linux/skbuff.h
 * __alloc_skb : skb->head = skb->data
 * all the space is referred to skb->data
 * skb_put(skb, len)
 * skb->tail += len
 * skb->len  += len
 * skb_tail_pointer returns skb->tail
 * to use it you must set skb_put(skb, 0)
 * so skb->tail point to skb->head = skb->data
 * skb_reset_tail_pointer(skb) returns skb->tail = skb->data
 */

int len = 30;
int lenskb = 100;

static struct audit_buffer *log_start(void);

struct audit_buffer{
	struct list_head 	list;
	struct sk_buff		*skb;
	gfp_t			gfp_mask;
};

static int skbuff_init(void)
{
	int lenp = 0;
	struct sk_buff *skb;
	struct audit_buffer *ab_bsm;

	struct nlmsghdr *nlh = NULL;

	printk(KERN_ALERT "skbuff_test starting\n");
	ab_bsm = log_start();
	skb = ab_bsm->skb;
	
	lenp = snprintf(skb_tail_pointer(skb), len, "This is a test");
	nlh = (struct nlmsghdr *)skb->data;
	printk(KERN_ALERT "%d %d: %s\n", strlen("This is a test"), lenp, (char *)NLMSG_DATA(nlh));
	skb_put(skb, lenp);
	lenp = snprintf(skb_tail_pointer(skb), len, "This is the test");
	printk(KERN_ALERT "%s\n", (char *)NLMSG_DATA(nlh));
	kfree(ab_bsm);
	return 0;
}

static struct audit_buffer *log_start(void)
{
	struct audit_buffer *ab_bsm = kmalloc(sizeof(*ab_bsm), GFP_KERNEL);
	struct nlmsghdr *nlh = NULL;

	ab_bsm->skb = alloc_skb(BUFSIZE, GFP_KERNEL);
	nlh = (struct nlmsghdr *)skb_put(ab_bsm->skb, NLMSG_SPACE(0));
	nlh->nlmsg_type = 0;
	nlh->nlmsg_flags = 0;
	nlh->nlmsg_pid = 0;
	nlh->nlmsg_seq = 0;
	return ab_bsm;
}

static void skbuff_exit(void)
{
	printk(KERN_ALERT "skbuff_test is exiting\n");
}

module_init(skbuff_init);
module_exit(skbuff_exit);
