#include "xdp_demo.h"

static __always_inline
void swap_ipv4(struct iphdr *ipv4)
{
    __u32 swap_ipv4 = ipv4->daddr;
    ipv4->daddr = ipv4->saddr;
    ipv4->saddr = swap_ipv4;
}

void swap_ipv6(struct ipv6hdr *ipv6)
{
    struct in6_addr swap_ipv6 = ipv6->daddr;
    ipv6->daddr = ipv6->saddr;
    ipv6->saddr = swap_ipv6;
}

static __always_inline
void swap_eth(struct ethhdr *eth)
{
    __u8 swap_eth[ETH_ALEN];
    memcpy(swap_eth, eth->h_dest, ETH_ALEN);
    memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
    memcpy(eth->h_source, swap_eth, ETH_ALEN);
}

static __always_inline
void debug_print(struct ethhdr *eth, struct udphdr *udp, struct dnshdr *dns)
{
    bpf_printk("0x%04x | UDP: %d -> %d | DNS: id:0x%04x flags:0x%04x",
        __bpf_htons(eth->h_proto),
        __bpf_htons(udp->source),
        __bpf_htons(udp->dest),
        __bpf_htons(dns->id),
        __bpf_htons(dns->flags.as_value)
    );
}

SEC("xdp/demo")
int xdp_prog(struct xdp_md *ctx)
{
    __u16 eth_proto;
    struct cursor c;
    struct ethhdr *eth;
    struct iphdr *ipv4;
    struct ipv6hdr *ipv6;
    struct udphdr *udp;
    struct dnshdr *dns;
 
    cursor_init(&c, ctx);
    if (!(eth = parse_eth(&c, &eth_proto)))
        return XDP_PASS;
    if (!(IS_IPV4(eth_proto) || IS_IPV6(eth_proto)))
        return XDP_PASS;
    if (IS_IPV4(eth_proto))
    {
        if (!(ipv4 = parse_iphdr(&c))
        ||  !(ipv4->protocol == IPPROTO_UDP))
            return XDP_PASS;
        if (!(udp = parse_udphdr(&c)) || !IS_DNS(udp))
            return XDP_PASS;
        if (!(dns = parse_dnshdr(&c)))
            return XDP_PASS;
        debug_print(eth, udp, dns);
        swap_ipv4(ipv4);
        swap_eth(eth);
        debug_v4("XDP", ipv4, udp);
    }
    if (IS_IPV6(eth_proto))
    {
        if (!(ipv6 = parse_ipv6hdr(&c))
        ||  !(ipv6->nexthdr == IPPROTO_UDP))
            return XDP_PASS;
        if (!(udp = parse_udphdr(&c)) || !IS_DNS(udp))
            return XDP_PASS;
        if (!(dns = parse_dnshdr(&c)))
            return XDP_PASS;
        debug_print(eth, udp, dns);
        swap_ipv6(ipv6);
        swap_eth(eth);
        debug_v6(ipv6, udp);
    }

    return XDP_TX;
}

char _license[] SEC("license") = "GPL";