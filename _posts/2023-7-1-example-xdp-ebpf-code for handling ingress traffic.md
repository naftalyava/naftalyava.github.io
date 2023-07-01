---
layout: post
title: "Exploring eBPF and XDP: An Example"
date: 2023-07-01
---

A year ago, I was exploring a few Kubernetes CNI plugins when I stumbled upon the intriguing Cilium project. Cilium uses **eBPF** and **XDP** for network traffic control, security, and visibility.

*eBPF* (Extended Berkeley Packet Filter) allows you to attach your code on the fly to almost any function within the Linux kernel. *XDP* (Xpress DataPath), on the other hand, enables manipulation of network traffic even before it reaches the network stack of the Linux kernel. Essentially, eBPF and XDP let you dynamically add logic to network traffic control while bypassing the kernel potentially giving you better performance.

Although I initially considered utilizing these technologies to accelerate Kubernetes workloads using a DPU, a type of smart NIC, I eventually pursued a different direction. However, the concepts of eBPF and XDP piqued my interest and stuck with me.

Fast forward to today, I decided to spend a weekend building a functional example that uses most of the basic building blocks of eBPF and XDP.

## What the code does?
- User-space configures IP addresses to which the `ping` command should be blocked; this configuration can be adjusted on the fly.
- User-space gets notified once ICMP traffic hits the NIC.

## How?
1. Utilize libbpf to abstract away many of the repeating eBPF boilerplate code, simplifying the process of writing, loading, and managing the eBPF program.
2. Establish communication between the user-space code and the eBPF program.
3. Utilize an eBPF ring buffer for communication where the XDP will be the initiator.
4. Use an eBPF hash map allowing user-space code to dynamically define which IPs should be blocked.

Let's break down the main parts of the eBPF code.


Allocation of the ring buffer and the hash map:

```C
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, uint32_t);
    __type(value, uint32_t);
} ping_hash SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} ringbuf SEC(".maps");
```


The actual XDP program which notifies user space on each ICMP packet together with the src and destination IP addresses.

```C
SEC("xdp")
int detect_ping(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct data_t msg = {0};
    int ret = XDP_PASS;

    struct ethhdr *eth = (struct ethhdr *)data;
    struct iphdr *ip = (struct iphdr *)((char *)data + sizeof(*eth));
    struct icmphdr *icmp = (struct icmphdr *)(ip + 1);

    if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*icmp) > data_end) {
        return  XDP_PASS;
    }

    if (eth->h_proto != htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    if (ip->protocol == 1) {
        msg.saddr = ip->saddr;
        msg.daddr = ip->daddr;

        bpf_ringbuf_output(&ringbuf, &msg, sizeof(msg), BPF_RB_FORCE_WAKEUP);

        if (bpf_map_lookup_elem(&ping_hash, &ip->daddr) || bpf_map_lookup_elem(&ping_hash, &ip->saddr)) {
            return XDP_DROP;
        } 

    }

    return ret;
}
```

Now let's turn our attention to the user-space code.
We utilize bpftool to generate all the boilerplate code needed for opening and loading the eBPF code.
Notice in the Makefile how we utilize bpftool to create the header file with all the auto generated code.

```C
struct main_bpf *skel = main_bpf__open_and_load();
if (!skel) {
    fprintf(stderr, "Failed to open BPF skeleton\n");
    return 1;
}
```

Attaching the XDP program to the network interface:
```C
struct bpf_link *link = bpf_program__attach_xdp(skel->progs.detect_ping, ifindex);
if (!link) {
    fprintf(stderr, "bpf_program__attach_xdp\n");
    return 1;
}
```

Handling the communication – ring buffer.
We are polling the buffer every 1 second, the buffer is updated by the XDP program.
```C
struct bpf_map *ringbuf_map = bpf_object__find_map_by_name(skel->obj, "ringbuf");
[...]
struct ring_buffer *ringbuf = ring_buffer__new(bpf_map__fd(ringbuf_map), handle_event, NULL, NULL);
[...]
while (1) {
    if (ring_buffer__poll(ringbuf, 1000 /* timeout, ms */) < 0) {
        fprintf(stderr, "Error polling ring buffer\n");
        break;
    }
}
```

Handling the communication – hash map [insertion of IPs to block in XDP].
```C
struct bpf_map *map_hash = bpf_object__find_map_by_name(skel->obj, "ping_hash");
// [...]
err = bpf_map__update_elem(map_hash, &ip_server, sizeof(uint32_t), &ip_server, sizeof(uint32_t), BPF_ANY);
```

The complete code can be found [here](https://github.com/naftalyava/ebpf_and_xdp_examples/tree/main/block_ping).

I also record a video where I explain the code in more detail:
<iframe width="368" height="207" src="https://youtu.be/clfDULDFeis" title="Exploring eBPF and XDP: An Example" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>

<iframe width="560" height="315" src="https://www.youtube.com/embed/clfDULDFeis" title="Exploring eBPF and XDP: An Example" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" allowfullscreen></iframe>