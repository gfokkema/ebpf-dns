#include "bpf_demo.h"
#include <linux/pkt_cls.h>

SEC("egress")
int read_dns(struct __sk_buff *skb)
{
    __u16 eth_proto;
    struct cursor c;
    struct ethhdr *eth;
    struct iphdr *ipv4;
    // struct ipv6hdr *ipv6;
    struct udphdr *udp;
    struct dnshdr *dns;

    __u8 *qname;
    struct dns_qrr *qrr;
 
    cursor_init(&c, skb);
    if (!(eth = parse_eth(&c, &eth_proto))
    ||  !(IS_IPV4(eth_proto) || IS_IPV6(eth_proto)))
        return TC_ACT_OK;

    if (IS_IPV4(eth_proto))
    {
        if (!(ipv4 = parse_iphdr(&c))
        ||  !(ipv4->protocol == IPPROTO_UDP)
        ||  !(udp = parse_udphdr(&c))
        ||  !IS_DNS(udp)
        ||  !(dns = parse_dnshdr(&c)))
            return TC_ACT_OK;

        debug_v4("TC IP4", ipv4, udp);
        debug_dns("TC DNS", dns);

        if (!IS_DNS_ANSWER(dns)
        ||  !(dns->flags.as_bits_and_pieces.tc))
        {
            bpf_printk("TC IP4: no answer or not truncated");
            return TC_ACT_OK;
        }
        bpf_printk("TC IP4: truncated, storing in map");

        __u8 size = (__u8*)qrr - (__u8*)qname;
        if (!(qname = parse_dname(&c, (void*)dns))
        ||  !(qrr = parse_dns_qrr(&c)))
            return TC_ACT_OK;

        debug_qrr("TC QRR", qrr, qname);

        if (size > sizeof(struct key))
            return TC_ACT_OK;

        struct key key = {0};
        bpf_probe_read_kernel(&key, size, qname);

        struct value *value = bpf_map_lookup_elem(&dns_results, &key);
        struct value newval = {1};
        if (value)
        {
            newval.count = value->count + 1;
            bpf_printk("TC MAP: %s: %d", key.domain, newval.count);
        }
        bpf_map_update_elem(&dns_results, &key, &newval, BPF_ANY);
    }

    return TC_ACT_OK;
}

SEC("ingress")
int write_dns(struct __sk_buff *skb)
{
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";