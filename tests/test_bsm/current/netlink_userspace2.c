#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/netlink.h>
#include <sys/socket.h>
#include <errno.h>
#include <fcntl.h>

#define MAX_PAYLOAD 1024

int main()
{
	int sock_fd, len;
	FILE *fp;
	struct sockaddr_nl dest_addr, src_addr;
	struct nlmsghdr *nlh;
	char buf[MAX_PAYLOAD];
	socklen_t addrsize = sizeof(src_addr);

	sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_UNUSED);
	memset(&dest_addr, 0, sizeof(dest_addr));
	memset(&src_addr, 0, sizeof(src_addr));

	/*filling the destination address*/
	dest_addr.nl_family = AF_NETLINK;
	dest_addr.nl_pid = 0; //destination is kernel space
	dest_addr.nl_groups = 0; //unicast
	
	/*filling the header*/
	nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
	nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
	nlh->nlmsg_pid = getpid(); //userspace app pid
	nlh->nlmsg_flags = 0;
	/*copying the message data*/
	strcpy(NLMSG_DATA(nlh), "Hello world");

	/*sending nlh through netlink socket*/
	sendto(sock_fd, nlh, nlh->nlmsg_len, 0, 
		(struct sockaddr *)&dest_addr, sizeof(dest_addr));
	
	/*receiving nlh through netlink socket*/
	len = recvfrom(sock_fd, buf, MAX_PAYLOAD, MSG_DONTWAIT, 
		(struct sockaddr *)&src_addr, &addrsize);
	printf("len: %d\n%s\n", len, strerror(errno));
	nlh = (struct nlmsghdr *)buf;
	fp = fopen("bsm_trail.bsm", "w+");
	fwrite(NLMSG_DATA(nlh), sizeof(u_char), len, fp);
	close(fp);
	//printf("userspace app: %s\n strlen: %d\n", 
	//	(char *)NLMSG_DATA(nlh), strlen((char *)NLMSG_DATA(nlh)));
	close(sock_fd);
	return 0;
}
