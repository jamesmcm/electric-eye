//! Bounded, stable-hash Bloom filter for seen network destinations.

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
const DEFAULT_ENTRIES: usize = 65_536;
const BITS_PER_ENTRY: usize = 16;
const HASHES: u32 = 7;

fn mix(parts: [&[u8]; 2], seed: u64) -> u64 {
    let mut hash = seed;
    for (index, part) in parts.into_iter().enumerate() {
        if index > 0 {
            hash ^= 0xff;
            hash = hash.wrapping_mul(FNV_PRIME);
        }
        for byte in part {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(FNV_PRIME);
        }
    }
    hash
}

#[derive(Clone, Debug)]
pub struct BloomFilter {
    words: Vec<u64>,
    bit_count: u64,
    hashes: u32,
}

impl Default for BloomFilter {
    fn default() -> Self {
        Self::for_entries(DEFAULT_ENTRIES)
    }
}

impl BloomFilter {
    pub fn for_entries(entries: usize) -> Self {
        let entries = entries.max(1_024);
        let bits = entries.saturating_mul(BITS_PER_ENTRY).max(64);
        let words = bits.div_ceil(64);
        Self {
            words: vec![0; words],
            bit_count: (words as u64) * 64,
            hashes: HASHES,
        }
    }

    fn position(&self, first: u64, second: u64, index: u32) -> usize {
        let bit = first.wrapping_add(u64::from(index).wrapping_mul(second | 1)) % self.bit_count;
        (bit / 64) as usize
    }

    fn mask(&self, first: u64, second: u64, index: u32) -> u64 {
        let bit = first.wrapping_add(u64::from(index).wrapping_mul(second | 1)) % self.bit_count;
        1u64 << (bit % 64)
    }

    fn hashes(application: &str, destination: &str) -> (u64, u64) {
        (
            mix([application.as_bytes(), destination.as_bytes()], FNV_OFFSET),
            mix(
                [destination.as_bytes(), application.as_bytes()],
                FNV_OFFSET ^ 0x9e37_79b9_7f4a_7c15,
            ),
        )
    }

    pub fn contains(&self, application: &str, destination: &str) -> bool {
        let (first, second) = Self::hashes(application, destination);
        (0..self.hashes).all(|index| {
            let word = self.position(first, second, index);
            self.words[word] & self.mask(first, second, index) != 0
        })
    }

    pub fn insert(&mut self, application: &str, destination: &str) {
        let (first, second) = Self::hashes(application, destination);
        for index in 0..self.hashes {
            let word = self.position(first, second, index);
            self.words[word] |= self.mask(first, second, index);
        }
    }

    #[cfg(test)]
    pub fn byte_len(&self) -> usize {
        self.words.len() * std::mem::size_of::<u64>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inserted_entries_are_always_reported_as_seen() {
        let mut filter = BloomFilter::for_entries(256);
        let keys: Vec<_> = (0..256)
            .map(|index| {
                (
                    format!("application-{index}"),
                    format!("192.0.2.{}:443", index % 200 + 1),
                )
            })
            .collect();
        for (application, destination) in &keys {
            filter.insert(application, destination);
        }
        for (application, destination) in &keys {
            assert!(filter.contains(application, destination));
        }
    }

    #[test]
    fn filter_memory_is_bounded_and_distinguishes_application_namespaces() {
        let filter = BloomFilter::for_entries(65_536);
        assert!(filter.byte_len() <= 256 * 1024);
        let mut filter = filter;
        filter.insert("firefox", "8.8.8.8:443");
        assert!(filter.contains("firefox", "8.8.8.8:443"));
        assert!(!filter.contains("curl", "8.8.8.8:443"));
    }
}
