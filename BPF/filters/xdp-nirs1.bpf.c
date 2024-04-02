#include "../vmlinux.h"
#include <bpf/bpf_helpers.h>

#define bpf_printk(fmt, ...)					\
({								\
	       char ____fmt[] = fmt;				\
	       bpf_trace_printk(____fmt, sizeof(____fmt),	\
				##__VA_ARGS__);			\
})

typedef struct dip_proto_dport {
        u32 dst_ip;
        u16 dst_port;
        u8 ip_proto;
} _dip_proto_dport;

typedef struct tsmp_sip_sport {
        u64 timestamp;
        u32 src_ip;
        u16 src_port;
} _tsmp_sip_sport;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192); //subject to change
    __type(key, _dip_proto_dport);
    __type(value, _tsmp_sip_sport);
} _nir1_map SEC(".maps");

SEC("xdp")
int nirs1(struct xdp_md *ctx)
{
    if (!ctx)
    {
        bpf_printk("[!] ***REMOVED*** no ctx\n");
        return XDP_PASS;
    }
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;
    struct ethhdr *eth = data;

     if (eth + 1 > (struct ethhdr *)data_end)
    {
        bpf_printk("[!] ***REMOVED*** no eth data\n");
        return XDP_DROP;
    }
    uint16_t ethertype;

    if (eth->h_proto != 0x0008)
    {
        bpf_printk("[!] ***REMOVED*** no ipv4\n");
        return XDP_PASS;
    }

    struct iphdr *iph = data + sizeof (struct ethhdr);
    struct ipv6hdr *ipv6_hdr = NULL;


    if (iph + 1 > (struct iphdr *)data_end)
    {
        bpf_printk("[!] ***REMOVED*** no ipheader\n");
        return XDP_DROP;
    }

    //TODO more types (possible switch case and/or helper func)
    if (iph->protocol == 6)
    {
        struct tcphdr *tcph = {0};
        if (iph)
            tcph = data + sizeof(struct ethhdr) + (iph->ihl * 4);
        else
        {
            bpf_printk("[!] ***REMOVED*** ipv6\n");
            return XDP_DROP;
        }

        if (tcph + 1 > (struct tcphdr *)data_end){
            bpf_printk("[!] ***REMOVED*** no tcp header\n");
            return XDP_DROP;
        }

        struct dip_proto_dport key = {0};
        struct tsmp_sip_sport new_value = {0};

        key.dst_ip = iph->daddr;
        key.ip_proto = iph->protocol;
        key.dst_port = tcph->dest;

        new_value.timestamp = bpf_ktime_get_boot_ns();
        new_value.src_ip = iph->saddr;
        new_value.src_port = tcph->source;

        bpf_map_update_elem(&_nir1_map, &key, &new_value, BPF_ANY);

        return XDP_PASS;
    }
    else if (iph->protocol == 17)
    {
        struct udphdr *udph = {0};
        if (iph)
            udph = data + sizeof(struct ethhdr) + (iph->ihl * 4);
        else
            return XDP_DROP;
        
        if (udph + 1 > (struct udphdr *)data_end){
            bpf_printk("[!] ***REMOVED*** no udp header\n");
            return XDP_DROP;
        }
        struct dip_proto_dport key = {0};
        struct tsmp_sip_sport new_value = {0};

        key.dst_ip = iph->daddr;
        key.ip_proto = iph->protocol;
        key.dst_port = udph->dest;

        new_value.timestamp = bpf_ktime_get_boot_ns();
        new_value.src_ip = iph->saddr;
        new_value.src_port = udph->source;

        bpf_map_update_elem(&_nir1_map, &key, &new_value, BPF_ANY);

        return XDP_PASS;
    }
    else if (iph->protocol == 132){
        struct sctphdr *sctph = {0};
        if (iph)
            sctph = data + sizeof(struct ethhdr) + (iph->ihl * 4);
        else
            return XDP_DROP;
        
        if (sctph + 1 > (struct sctphdr *)data_end){
            bpf_printk("[!] ***REMOVED*** no sctph header\n");
            return XDP_DROP;
        }
        struct dip_proto_dport key = {0};
        struct tsmp_sip_sport new_value = {0};

        key.dst_ip = iph->daddr;
        key.ip_proto = iph->protocol;
        key.dst_port = sctph->dest;

        new_value.timestamp = bpf_ktime_get_boot_ns();
        new_value.src_ip = iph->saddr;
        new_value.src_port = sctph->source;

        bpf_map_update_elem(&_nir1_map, &key, &new_value, BPF_ANY);

        return XDP_PASS;
    }
    else{
        bpf_printk("[!] ***REMOVED*** unknown proto\n");
        return XDP_DROP;
    }
    bpf_printk("[!] Func end\n");
    return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";