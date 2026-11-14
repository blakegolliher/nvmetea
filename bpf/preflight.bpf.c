// SPDX-License-Identifier: (MIT OR GPL-2.0)
/*
 * fentry attach preflight (docs/kernel-compatibility.md §8, finding F15).
 * Attaching fentry/fexit programs can stall for seconds on busy hosts (the
 * trampoline update waits for RCU-tasks grace periods). A helper process
 * attaches this one-instruction program to bpf_fentry_test1 (never called
 * outside BPF selftests) and reports how long it took; the parent abandons it
 * after a deadline and uses kprobes instead.
 */
#include "kernel_types.h"

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual MIT/GPL";

SEC("fentry/bpf_fentry_test1")
int nvt_preflight(void *ctx)
{
	return 0;
}
