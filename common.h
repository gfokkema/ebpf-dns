#pragma once

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define memcpy __builtin_memcpy

#define DNS_PORT 53

#define IS_IPV4(P) P == __bpf_htons(ETH_P_IP)
#define IS_IPV6(P) P == __bpf_htons(ETH_P_IPV6)
#define IS_VLAN(P) P == __bpf_htons(ETH_P_8021Q) || P == __bpf_htons(ETH_P_8021AD)

#define IS_PORT(U, P)    (__bpf_htons(U->source) == P || __bpf_htons(U->dest) == P)
#define IS_DNS(U)        IS_PORT(U, DNS_PORT)
#define IS_DNS_ANSWER(P) (__bpf_ntohs(P->arcount) > 0)

struct cursor
{
    void *pos;
    void *end;
};

struct vlanhdr {
    __u16 tci;
    __u16 encap_proto;
};

struct dnshdr {
    __u16 id;
    union {
        struct {
            __u8  rd     : 1;
            __u8  tc     : 1;
            __u8  aa     : 1;
            __u8  opcode : 4;
            __u8  qr     : 1;

            __u8  rcode  : 4;
            __u8  cd     : 1;
            __u8  ad     : 1;
            __u8  z      : 1;
            __u8  ra     : 1;
        }        as_bits_and_pieces;
        __u16 as_value;
    } flags;
    __u16 qdcount;
    __u16 ancount;
    __u16 nscount;
    __u16 arcount;
};

struct dns_qrr {
    __u16 qtype;
    __u16 qclass;
};

struct key {
    __u8 domain[64];  // max label len = 63
};

struct value {
    __u64 count;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, struct key);
    __type(value, struct value);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} dns_results SEC(".maps");

#define PARSE_FUNC_DECLARATION(STRUCT)              \
static __always_inline                              \
struct STRUCT *parse_ ## STRUCT (struct cursor *c)  \
{                                                   \
    struct STRUCT *ret = c->pos;                    \
    if (c->pos + sizeof(struct STRUCT) > c->end)    \
        return 0;                                   \
    c->pos += sizeof(struct STRUCT);                \
    return ret;                                     \
}

PARSE_FUNC_DECLARATION(ethhdr)
PARSE_FUNC_DECLARATION(vlanhdr)
PARSE_FUNC_DECLARATION(iphdr)
PARSE_FUNC_DECLARATION(ipv6hdr)
PARSE_FUNC_DECLARATION(udphdr)
PARSE_FUNC_DECLARATION(dnshdr)
PARSE_FUNC_DECLARATION(dns_qrr)

static __always_inline
struct ethhdr *parse_eth(struct cursor *c, __u16 *eth_proto)
{
    struct ethhdr  *eth;

    if (!(eth = parse_ethhdr(c)))
        return 0;

    *eth_proto = eth->h_proto;
    if (IS_VLAN(*eth_proto)) {
        struct vlanhdr *vlan;

        if (!(vlan = parse_vlanhdr(c)))
            return 0;

        *eth_proto = vlan->encap_proto;
        if (IS_VLAN(*eth_proto)) {
            if (!(vlan = parse_vlanhdr(c)))
                return 0;

            *eth_proto = vlan->encap_proto;
        }
    }
    return eth;
}

static __always_inline
__u8 *parse_dname(struct cursor *c, __u8 *pkt)
{
    __u8 *dname = c->pos;

    int  i;
    for (i = 0; i < 128; i++) { /* Maximum 128 labels */
        __u8 o;
        if (c->pos + 1 > c->end)
            return 0;

        o = *(__u8 *)c->pos;
        if ((o & 0xC0) == 0xC0) {
            /* Compression label, Only back references! */
            if ((o | 0x3F) >= (dname - pkt))
                return 0;

            /* Compression label is last label of dname. */
            c->pos += 1;
            break;
        } else if (o & 0xC0)
            /* Unknown label type */
            return 0;

        c->pos += o + 1;
        if (!o)
            break;
    }
    return dname;
}


static __always_inline
void debug_print(char* pre, struct ethhdr *eth, struct udphdr *udp, struct dnshdr *dns)
{
    bpf_printk("%s: 0x%04x | UDP: %d -> %d | DNS: id:0x%04x flags:0x%04x",
        pre,
        __bpf_htons(eth->h_proto),
        __bpf_htons(udp->source),
        __bpf_htons(udp->dest),
        __bpf_htons(dns->id),
        __bpf_htons(dns->flags.as_value)
    );
}

static __always_inline
void debug_v4(char* pre, struct iphdr *ipv4, struct udphdr *udp)
{
    __u8 saddr[4];
    __u8 daddr[4];
    memcpy(saddr, &ipv4->saddr, 4);
    memcpy(daddr, &ipv4->daddr, 4);
    bpf_printk("%s: %d.%d.%d.%d -> %d.%d.%d.%d",
        pre,
        saddr[0], saddr[1], saddr[2], saddr[3],
        daddr[0], daddr[1], daddr[2], daddr[3]
    );
}

static __always_inline
void debug_v6(struct ipv6hdr *ipv6, struct udphdr *udp)
{

}

static __always_inline
void debug_dns(char* pre, struct dnshdr *dns)
{
    bpf_printk("%s: id:%d tc: %d qd:%d an:%d",
        pre,
        __bpf_htons(dns->id),
        dns->flags.as_bits_and_pieces.tc,
        __bpf_htons(dns->qdcount),
        __bpf_htons(dns->ancount)
    );
}

static __always_inline
void debug_qrr(char* pre, struct dns_qrr* qrr, __u8* qname)
{
    bpf_printk("%s: qcls:%d qty:%d | %s",
        pre,
        __bpf_htons(qrr->qclass),
        __bpf_htons(qrr->qtype),
        qname
    );
}

static __always_inline
int debug_return(char* msg, __u8 ret)
{
    bpf_printk("TC IP4: not truncated");
    return ret;
}