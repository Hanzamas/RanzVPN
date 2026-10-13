//
// XDP eBPF spike (ADR-0018): redirect every frame the XDP eBPF hook sees to
// the AF_XDP socket in xsk_map[rx_queue_index], and count what the hook saw
// so user mode can tell "hook never ran" from "redirect failed".
//
// Based on test/bpf/xsk_redirect.c and samples/xskfwd/bpf/xskfwd_redirect.c
// of microsoft/xdp-for-windows release/1.4 (MIT). Spike code, never merged.
//
// Build (see ../build-bpf.ps1):
//   clang -g -target bpf -O2 -I <ebpf>/include -I <ebpf>/include/uapi -I <xdp-sdk>/include -c ranz_xsk.c
//   Convert-BpfToNative.ps1 -FileName ranz_xsk -KernelMode $true
//

#include "bpf_helpers.h"
#include "xdp/ebpfhook.h"

struct
{
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __type(key, uint64_t);
    __type(value, void *);
    __uint(max_entries, 64);
} xsk_map SEC(".maps");

//
// stats[0] = every frame, [1] = IPv4/UDP to port 5555 (OS -> peer, the
// TX-inspect test traffic), [2] = IPv4/UDP to port 5556 (injected
// peer -> OS), [3] = ARP.
//
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, uint64_t);
    __uint(max_entries, 4);
} stats SEC(".maps");

#define BUMP(K)                                               \
    do {                                                      \
        uint32_t Key_ = (K);                                  \
        uint64_t *Val_ = bpf_map_lookup_elem(&stats, &Key_);  \
        if (Val_) {                                           \
            *Val_ += 1;                                       \
        }                                                     \
    } while (0)

SEC("xdp/ranz_xsk")
int
ranz_xsk(xdp_md_t *ctx)
{
    unsigned char *p = (unsigned char *)ctx->data;
    unsigned char *end = (unsigned char *)ctx->data_end;

    BUMP(0);

    //
    // Only IHL 5 is parsed; the spike's own frames never carry IP options.
    //
    if (p + 14 + 20 + 8 <= end && p[12] == 0x08 && p[13] == 0x00 && p[14] == 0x45 && p[23] == 17) {
        uint16_t Port = (uint16_t)((p[36] << 8) | p[37]);
        if (Port == 5555) {
            BUMP(1);
        } else if (Port == 5556) {
            BUMP(2);
        }
    } else if (p + 14 <= end && p[12] == 0x08 && p[13] == 0x06) {
        BUMP(3);
    }

    return bpf_redirect_map(&xsk_map, ctx->rx_queue_index, XDP_PASS);
}
