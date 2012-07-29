#include <linux/init.h>
#include <linux/module.h>
/* linux/list.h for double linked list kernel impl*/
#include <linux/list.h>
/* linux/slab.h for kmalloc() */
#include <linux/slab.h>

static LIST_HEAD(list);
struct buffer{
	struct list_head list; //for double linked lists
	char	test[30];
};

static int __init list_init(void)
{
	struct buffer *buf, *buf2;
	int i;
	//alloc for struct buffer
	buf = kmalloc(sizeof(*buf), GFP_KERNEL);
	printk(KERN_ALERT "list_test starting\n");
	//inserting stuff into the struct
	snprintf(buf->test, sizeof(buf->test), "This is a test");
	printk(KERN_ALERT "buf->test: %s\n", buf->test);
	//creating the 2 items of the list
	//list.next points to list of struct buffer
	buf2 = list_entry(list.next, struct buffer, list);
	snprintf(buf2->test, sizeof(buf2->test), "This is the second test");
	printk(KERN_ALERT "buf2->test: %s\n", buf2->test);
	list_del(buf2);
	kfree(buf);
	return 0;
}

static void __exit list_exit(void)
{
	printk(KERN_ALERT "list_test exiting\n");
}

module_init(list_init);
module_exit(list_exit);

