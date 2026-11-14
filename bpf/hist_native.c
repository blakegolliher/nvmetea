// SPDX-License-Identifier: (MIT OR GPL-2.0)
/* Native build of the BPF bucket function, for the Rust equivalence test. */
#include <stdint.h>
typedef uint32_t u32;
typedef uint64_t u64;
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif
#include "nvmetea.h"
#include "hist.bpf.h"

uint32_t nvt_bucket_native(uint64_t v) { return nvt_bucket(v); }
