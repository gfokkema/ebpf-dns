#include "xdp_demo.h"

static __always_inline
void swap_udp(struct udphdr *udp)
{
    __u16 swap_udp = udp->dest;
    udp->dest = udp->source;
    udp->source = swap_udp;
}

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

    __u8 *qname;
    struct dns_qrr *qrr;
 
    cursor_init(&c, ctx);
    if (!(eth = parse_eth(&c, &eth_proto)))
        return XDP_PASS;
    if (!(IS_IPV4(eth_proto) || IS_IPV6(eth_proto)))
        return XDP_PASS;
    if (IS_IPV4(eth_proto))
    {
        if (!(ipv4 = parse_iphdr(&c))
        ||  !(ipv4->protocol == IPPROTO_UDP)
        ||  !(udp = parse_udphdr(&c))
        ||  !IS_DNS(udp)
        ||  !(dns = parse_dnshdr(&c))
        ||  !(qname = parse_dname(&c, (void*)dns))
        ||  !(qrr = parse_dns_qrr(&c))
        )
            return XDP_PASS;

        __u8 size = (__u8*)qrr - (__u8*)qname;
        if (size > sizeof(struct key))
            return XDP_PASS;

        struct key key = {0};
        bpf_probe_read_kernel(&key, size, qname);
        struct value *value = bpf_map_lookup_elem(&dns_results, &key);
        if (!value)  // Should check OPT record size
            return XDP_PASS;

        debug_print("XDP", eth, udp, dns);
        debug_v4("XDP", ipv4, udp);
        bpf_printk("XDP: %s -> %d", qname, value->count);

        swap_udp(udp);
        swap_ipv4(ipv4);
        swap_eth(eth);
        dns->flags.as_bits_and_pieces.qr = 1;
        dns->flags.as_bits_and_pieces.tc = 1;
        dns->flags.as_bits_and_pieces.ra = 1;
        return XDP_TX;
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
        debug_print("XDP", eth, udp, dns);
        swap_ipv6(ipv6);
        swap_eth(eth);
        debug_v6(ipv6, udp);
    }

    return XDP_TX;
}

char _license[] SEC("license") = "GPL";