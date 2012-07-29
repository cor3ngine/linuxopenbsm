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

struct wrapper_buffer{
	struct buffer buf;
	int len;
};

/* mylist is list_head type
 * LIST_HEAD macro declares and initializes the list
 */
//LIST_HEAD(mylist); 

static int __init list_init(void)
{
	struct buffer *buf_list, *buf;
	struct wrapper_buffer *wrp;
	struct list_head *pos, *q;
	int i;
	
	printk(KERN_ALERT "list_test2 is starting\n");
	wrp = kmalloc(sizeof(*wrp), GFP_KERNEL);
	buf_list = &(wrp->buf);
	INIT_LIST_HEAD(&(buf_list->list));
	wrp->len = 1;

	for(i = 0; i < 4; i++)
	{
		
		/* allocating space for the istance of struct buffer
		 * that will be added to mylist and working on it
		 */
		buf = kmalloc(sizeof(*buf), GFP_KERNEL);
		snprintf(buf->string, sizeof(buf->string), "This is a test %d", i);
		
		/* adding the istance to mylist */
		list_add_tail(&(buf->list), &(buf_list->list));
	}

	/* printing the list items */
	printk(KERN_ALERT "list_for_each: \n");
	list_for_each(pos, &(buf_list->list))
	{
		buf = list_entry(pos, struct buffer, list);
		printk(KERN_ALERT "%s\n", buf->string);
	}

	/* printing the list items and freeing the space allocated
	 * for them
	 */
	printk(KERN_ALERT "list_for_each_safe: \n");
	list_for_each_safe(pos, q, &(buf_list->list))
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
