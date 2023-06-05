#include "bpf_demo.h"
#include <linux/pkt_cls.h>

SEC("tc")
int read_dns(struct __sk_buff *skb)
{
    __u16 eth_proto;
    struct cursor c;
    struct ethhdr *eth;
    struct iphdr *ipv4;
    struct ipv6hdr *ipv6;
    struct udphdr *udp;
    struct dnshdr *dns;
 
    cursor_init(&c, skb);
    if (!(eth = parse_eth(&c, &eth_proto)))
        return TC_ACT_OK;
    if (!(IS_IPV4(eth_proto) || IS_IPV6(eth_proto)))
        return TC_ACT_OK;
    if (IS_IPV4(eth_proto))
    {
        if (!(ipv4 = parse_iphdr(&c))
        ||  !(ipv4->protocol == IPPROTO_UDP))
            return TC_ACT_OK;
        if (!(udp = parse_udphdr(&c)) || !IS_DNS(udp))
            return TC_ACT_OK;
        if (!(dns = parse_dnshdr(&c)))
            return TC_ACT_OK;
        debug_v4("TC", ipv4, udp);
    }

    return TC_ACT_OK;
}

SEC("tc")
int write_dns(struct __sk_buff *skb)
{
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";