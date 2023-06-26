#include "bpf_demo.h"
#include <linux/pkt_cls.h>

static __always_inline
int outgoing_udp_dns(struct cursor c, struct iphdr *ip, struct udphdr *udp, struct dnshdr *dns)
{
    debug_v4("TC UDP IP4", ip, udp->source, udp->dest);
    debug_dns("TC UDP DNS", dns);

    if (!(dns->flags.as_bits_and_pieces.tc))
    {
        bpf_printk("TC UDP IP4: not truncated");
        return TC_ACT_OK;
    }
    bpf_printk("TC UDP IP4: truncated, storing in map");

    __u8 *qname;
    struct dns_qrr *qrr;
    if (!(qname = parse_dname(&c, (void*)dns))
    ||  !(qrr = parse_dns_qrr(&c)))
        return TC_ACT_OK;
    debug_qrr("TC UDP QRR", qrr, qname);

    __u8 size = (__u8*)qrr - (__u8*)qname;
    if (size > sizeof(struct key))
        return TC_ACT_OK;

    struct key key = {qrr->qtype, qrr->qclass, {0}};
    bpf_probe_read_kernel(&key.domain, size, qname);

    struct value *value = bpf_map_lookup_elem(&dns_results, &key);
    struct value newval = {1, 0};
    if (value)
    {
        newval.count = value->count + 1;
        newval.size = value->size;
        debug_map("TC UDP MAP", &key, &newval);
    }
    bpf_map_update_elem(&dns_results, &key, &newval, BPF_ANY);

    return TC_ACT_OK;
}

static __always_inline
int outgoing_tcp_dns(struct cursor c, struct iphdr *ip, struct tcphdr *tcp, struct tcpdnshdr *dns)
{
    debug_v4("TC TCP IP4", ip, tcp->source, tcp->dest);
    debug_dns("TC TCP DNS", &dns->dnshdr);

    __u8 *qname;
    struct dns_qrr *qrr;
    if (!(qname = parse_dname(&c, (void*)dns))
    ||  !(qrr = parse_dns_qrr(&c)))
        return TC_ACT_OK;
    debug_qrr("TC TCP QRR", qrr, qname);

    __u8 size = (__u8*)qrr - (__u8*)qname;
    if (size > sizeof(struct key))
        return TC_ACT_OK;

    struct key key = {qrr->qtype, qrr->qclass, {0}};
    struct value *value = bpf_map_lookup_elem(&dns_results, &key);
    if (value)
    {
        struct value newval = {value->count, __bpf_htons(dns->length)};
        bpf_map_update_elem(&dns_results, &key, &newval, BPF_ANY);
        debug_map("TC TCP MAP", &key, &newval);
    }

    return TC_ACT_OK;
}

SEC("egress")
int read_dns(struct __sk_buff *skb)
{
    __u16 eth_proto;
    struct cursor c;
    struct ethhdr *eth;
    struct iphdr *ip4;
    // struct ipv6hdr *ipv6;
    struct udphdr *udp;
    struct tcphdr *tcp;
    struct dnshdr *dns;
    struct tcpdnshdr *tcpdns;
 
    bpf_skb_pull_data(skb, skb->len);
    cursor_init(&c, skb);
    if (!(eth = parse_eth(&c, &eth_proto)))
        return TC_ACT_OK;

    if (IS_IPV4(eth_proto))
    {
        if (!(ip4 = parse_iphdr(&c)))
            return TC_ACT_OK;

        if (ip4->protocol == IPPROTO_UDP)
        {
            if (!(udp = parse_udphdr(&c)) || !IS_DNS(udp)
            ||  !(dns = parse_dnshdr(&c)) || !IS_DNS_ANSWER(dns))
                return TC_ACT_OK;
            return outgoing_udp_dns(c, ip4, udp, dns);
        }

        if (ip4->protocol == IPPROTO_TCP)
        {
            if (!(tcp    = parse_tcp(&c))       || !IS_DNS(tcp)
            ||  !(tcpdns = parse_tcpdnshdr(&c)) || !IS_DNS_ANSWER(&tcpdns->dnshdr))
                return TC_ACT_OK;
            return outgoing_tcp_dns(c, ip4, tcp, tcpdns);
        }
    }

    return TC_ACT_OK;
}

SEC("ingress")
int write_dns(struct __sk_buff *skb)
{
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";