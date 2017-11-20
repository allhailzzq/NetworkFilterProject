#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/ip.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("zzq & lx");

static int block = 0;
static int block_in = 0;
static int block_out = 0;


static char *block_ip = "no specific ip";

module_param(block, int, 0);
module_param(block_in, int, 0);
module_param(block_out, int, 0);
module_param(block_ip, charp, 0);

/* This function to be called by hook. */
typedef unsigned int nf_hookfn(void *priv, struct sk_buff *skb,
    const struct nf_hook_state *state)
{
    printf(KERN_INFO "drop packet\n");
    return NF_DROP;
}

typedef unsigned int nf_hookfn_ip(void *priv, struct sk_buff *skb,
    const struct nf_hook_state *state)
{
    struct iphdr* iph = ip_hdr(skb);

    char source_ip[16];
    snprintf(source_ip, 16, "%pI4", &iph->saddr);

    if(!strcmp(block_ip, source_ip)){
        printf(KERN_INFO "drop packet\n");
        return NF_DROP;
    }

    return NF_ACCEPT;
}

static struct nf_hook_ops hook_in = {
    .hook       = nf_hookfn,
    .hooknum    = NF_IP_LOCAL_IN
    .pf         = PF_INET,
    .priority   = NF_IP_PRI_FIRST,
};

static struct nf_hook_ops hook_out = {
    .hook       = nf_hookfn,
    .hooknum    = NF_IP_LOCAL_OUT
    .pf         = PF_INET,
    .priority   = NF_IP_PRI_FIRST,
};

static struct nf_hook_ops hook_sp = {
    .hook       = nf_hookfn_ip,
    .hooknum    = NF_IP_LOCAL_FORWARD
    .pf         = PF_INET,
    .priority   = NF_IP_PRI_FIRST,
};

static int __init init_nf(void)
{
    printk(KERN_INFO "Register netfilter module.\n");

    if (block_in == 1){
        nf_register_hook(&hook_in);
    }
    if (block_out == 1){
        nf_register_hook(&hook_out);
    }
    if (block_ip != "no specific ip"){
        nf_register_hook(&hook_sp);
    }



    return 0;
}

static void __exit exit_nf(void)
{
    printk(KERN_INFO "Unregister netfilter module.\n");
    nf_unregister_hook(&nfho);
}

module_init(init_nf);
module_exit(exit_nf);