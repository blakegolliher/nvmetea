/* SPDX-License-Identifier: (MIT OR GPL-2.0) */
/*
 * Log-linear bucket index (see nvmetea.h). Uses a shift ladder: the LLVM BPF
 * backend does not support CTLZ for every target/version.
 * Mirrored by nvmetea_core::model::nvme::bucket_index (shared test vectors).
 */
#ifndef NVMETEA_HIST_BPF_H
#define NVMETEA_HIST_BPF_H

static __always_inline u32 nvt_bucket(u64 v)
{
	u64 x;
	u32 k = 0;

	if (v < 256)
		return 0;
	if (v >= (1ULL << 36))
		return NVT_HIST_USED - 1;
	x = v;
	if (x >> 32) { x >>= 32; k += 32; }
	if (x >> 16) { x >>= 16; k += 16; }
	if (x >> 8)  { x >>= 8;  k += 8; }
	if (x >> 4)  { x >>= 4;  k += 4; }
	if (x >> 2)  { x >>= 2;  k += 2; }
	if (x >> 1)  { k += 1; }
	/* k in [8, 35] */
	return 1 + (k - 8) * 8 + (u32)((v >> (k - 3)) & 7);
}

#endif
