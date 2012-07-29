#include <linux/init.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <net/sock.h>
#include <net/netlink.h>
#include <linux/kthread.h>

#define BUFFER 1024

void netlink_receive(struct sk_buff *skb);
void netlink_send(void);

static struct task_struct *ksend_task;
static DECLARE_WAIT_QUEUE_HEAD(ksend_wait);

struct sock *nl_sk;
int nlk_pid = 0;

/* ksend_thread starts after calling kthread_run in 
 * netlink_receive
 * 
 * ksend_thread: init the wait queue
 * sets the current task as INTERRUPTIBLE (ready to sleep)
 * adds the current task to the wait queue
 * if nlk_pid == 0 ksend_thread goes to sleep calling schedule()
 * else sets the current task as RUNNING and dequeues it
 * from the wait queue
 * calls netlink_send()
 *
 * netlink_receive() after setting nlk_pid wakes ksend_thread
 * calling wake_up_interruptible
 */
static int ksend_thread(void *dummy)
{
	DECLARE_WAITQUEUE(wait, current);
	set_current_state(TASK_INTERRUPTIBLE);
	add_wait_queue(&ksend_wait, &wait);
	if(!nlk_pid){
		schedule();
	}
	__set_current_state(TASK_RUNNING);
	remove_wait_queue(&ksend_wait, &wait);
	netlink_send();
	return 0;
}

static int __init netlink_init(void)
{	
	printk(KERN_ALERT "kthread_test is starting\n");
	nl_sk = netlink_kernel_create(&init_net, NETLINK_UNUSED, 0,
				netlink_receive, NULL, THIS_MODULE);
	if(!nl_sk)
		printk(KERN_ALERT "error while initiliazing netlink"
				"socket\n");
	return 0;
}

void netlink_receive(struct sk_buff *skb)
{
	struct nlmsghdr *nlh;
	
	ksend_task = kthread_run(ksend_thread, NULL, "ksend");
	nlh = (struct nlmsghdr *)skb->data;
	printk(KERN_ALERT "%s\n",(char *)NLMSG_DATA(nlh));
	/* userspace app pid */
	nlk_pid = NETLINK_CB(skb).pid;
	printk(KERN_ALERT "nlk_pid: %d\n", nlk_pid);
	wake_up_interruptible(&ksend_wait);
}

void netlink_send(void)
{
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	int a = strlen("Hi from the kernel");
	int b = strlen("Test 2");

	skb = alloc_skb(BUFFER, GFP_KERNEL);
	nlh = (struct nlmsghdr *)skb_put(skb, NLMSG_SPACE(0));
	nlh->nlmsg_flags = 0;
	nlh->nlmsg_pid = 0;
	nlh->nlmsg_seq = 0;
	memcpy(skb_tail_pointer(skb), "Hi from the kernel", strlen("Hi from the kernel")+1);
	skb_put(skb, strlen("Hi from the kernel"));
	memcpy(skb_tail_pointer(skb), "Test 2", strlen("Test 2")+1);
	skb_put(skb, strlen("Test 2"));
	nlh->nlmsg_len = skb->len - NLMSG_SPACE(0);
	printk(KERN_ALERT "a: %d b: %d skb->len: %d\n", a, b, skb->len - NLMSG_SPACE(0));
	netlink_unicast(nl_sk, skb, nlk_pid, 0);

}

static void __exit netlink_exit(void)
{
	sock_release(nl_sk->sk_socket);
	printk(KERN_ALERT "kthread_test is exiting\n");
}

module_init(netlink_init);
module_exit(netlink_exit);

