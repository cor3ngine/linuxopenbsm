#include <linux/init.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/slab.h>

/* creating the type of my list elements */
struct buffer{
	/* this is REQUIRED for a kernel space
	 * list implementation
	 */
	struct list_head list; 
	char	string[30];
};

/* mylist is list_head type
 * LIST_HEAD macro declares and initializes the list
 */
LIST_HEAD(mylist); 

static int __init list_init(void)
{
	struct buffer *buf;
	struct list_head *pos, *q;
	int i;
	
	printk(KERN_ALERT "list_test2 is starting\n");
	for(i = 0; i < 4; i++)
	{
		
		/* allocating space for the istance of struct buffer
		 * that will be added to mylist and working on it
		 */
		buf = kmalloc(sizeof(*buf), GFP_KERNEL);
		snprintf(buf->string, sizeof(buf->string), "This is a test");
		
		/* adding the istance to mylist */
		list_add(&(buf->list), &(mylist));
	}

	/* printing the list items */
	printk(KERN_ALERT "list_for_each: \n");
	list_for_each(pos, &mylist)
	{
		buf = list_entry(pos, struct buffer, list);
		printk(KERN_ALERT "%s\n", buf->string);
	}

	/* printing the list items and freeing the space allocated
	 * for them
	 */
	printk(KERN_ALERT "list_for_each_safe: \n");
	list_for_each_safe(pos, q, &mylist)
	{
		buf = list_entry(pos, struct buffer, list);
		printk(KERN_ALERT "%s\n", buf->string);
		list_del(pos);
		kfree(buf);
	}

	return 0;
}

static void __exit list_exit(void)
{
	printk(KERN_ALERT "list_test2 is exiting\n");
}

module_init(list_init);
module_exit(list_exit);
