#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>

static struct nf_hook_ops nfho;

unsigned int hook_func (void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct iphdr *ip_header = ip_hdr(skb);
	struct tcphdr *tcp_header;
	if (ip_header->protocol == 6)
	{
		//printk (KERN_INFO "netfilter: TCP Packet Detected\n");
		tcp_header = tcp_hdr(skb);


		// NULL Scan -> No flags set
		if (tcp_header->syn == 0 && tcp_header->ack == 0 && tcp_header->urg == 0 && tcp_header->fin == 0 && tcp_header->psh == 0 && tcp_header->rst == 0)
		{
			printk (KERN_INFO "netfilter: TCP NULL Scan detected\n");
		}

		// XMAS Scan -> FIN, PSH and URG flags set
		if (tcp_header->syn == 0 && tcp_header->ack == 0 && tcp_header->urg == 1 && tcp_header->fin == 1 && tcp_header->psh == 1 && tcp_header->rst == 0)
		{
			printk (KERN_INFO "netfilter: TCP XMAS Scan detected\n");
		}

		// Maimon Scan -> FIN and ACK flags set
		if (tcp_header->syn == 0 && tcp_header->ack == 1 && tcp_header->urg == 0 && tcp_header->fin == 1 && tcp_header->psh == 0 && tcp_header->rst == 0)
		{
			printk (KERN_INFO "netfilter: TCP Maimon Scan detected\n");
		}

		// FIN Scan -> FIN flag set
		if (tcp_header->syn == 0 && tcp_header->ack == 0 && tcp_header->urg == 0 && tcp_header->fin == 1 && tcp_header->psh == 0 && tcp_header->rst == 0)
		{
			printk (KERN_INFO "netfilter: TCP FIN Scan detected\n");
		}

		// ACK Scan -> ACK flag set
		if (tcp_header->syn == 0 && tcp_header->ack == 1 && tcp_header->urg == 0 && tcp_header->fin == 0 && tcp_header->psh == 0 && tcp_header->rst == 0)
		{
			printk (KERN_INFO "netfilter: TCP ACK Scan detected\n");
		}

	}
	return NF_ACCEPT;
}

int init_module ()
{
	nfho.hook = hook_func;
	nfho.hooknum = NF_INET_PRE_ROUTING;
	nfho.pf = PF_INET;
	nfho.priority = NF_IP_PRI_FIRST;
	nf_register_net_hook(&init_net, &nfho);

	return 0;
}

void cleanup_module ()
{
	nf_unregister_net_hook(&init_net, &nfho);
}