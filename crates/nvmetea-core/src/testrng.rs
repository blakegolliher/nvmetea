//! Deterministic pseudo-random bytes for robustness tests (xorshift64*).
//! Seeded, so a failure reproduces.

pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng(seed | 1)
    }
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 { 0 } else { (self.next_u64() % n as u64) as usize }
    }
    pub fn bytes(&mut self, max: usize) -> Vec<u8> {
        let n = self.below(max + 1);
        (0..n).map(|_| self.next_u64() as u8).collect()
    }
    /// A mutation of `seed`: bit flips, overwrites, truncation, duplication, splices.
    pub fn mutate(&mut self, seed: &[u8]) -> Vec<u8> {
        let mut v = seed.to_vec();
        for _ in 0..=self.below(8) {
            match self.below(6) {
                0 if !v.is_empty() => {
                    let i = self.below(v.len());
                    v[i] ^= 1 << self.below(8);
                }
                1 if !v.is_empty() => {
                    let i = self.below(v.len());
                    v[i] = self.next_u64() as u8;
                }
                2 => v.truncate(self.below(v.len() + 1)),
                3 if !v.is_empty() => {
                    let i = self.below(v.len());
                    let j = (i + self.below(32)).min(v.len());
                    let chunk = v[i..j].to_vec();
                    let at = self.below(v.len() + 1);
                    v.splice(at..at, chunk);
                }
                4 => {
                    let at = self.below(v.len() + 1);
                    let junk = self.bytes(16);
                    v.splice(at..at, junk);
                }
                _ if !v.is_empty() => {
                    // extreme integers at a random 4-byte position
                    let i = self.below(v.len());
                    let val = [0u32, 1, u32::MAX, 0x7fff_ffff, 0x8000_0000][self.below(5)].to_ne_bytes();
                    for (k, b) in val.iter().enumerate() {
                        if let Some(x) = v.get_mut(i + k) {
                            *x = *b;
                        }
                    }
                }
                _ => {}
            }
        }
        v
    }
}
