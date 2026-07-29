/// ISAAC-64: A fast cryptographic PRNG used for WeChat Channels video decryption.
///
/// Ported from the CipherTalk TypeScript implementation which matches
/// WeChat's standard ISAAC-64 with big-endian keystream and reverse-index consumption.
pub struct Isaac64 {
    mm: [u64; 256],
    randrsl: [u64; 256],
    aa: u64,
    bb: u64,
    cc: u64,
    randcnt: usize,
}

impl Isaac64 {
    pub fn new(seed: u64) -> Self {
        let mut rng = Isaac64 {
            mm: [0u64; 256],
            randrsl: [0u64; 256],
            aa: 0,
            bb: 0,
            cc: 0,
            randcnt: 0,
        };
        rng.randrsl[0] = seed;
        rng.init();
        rng
    }

    pub fn next_u64(&mut self) -> u64 {
        if self.randcnt == 0 {
            self.generate();
            self.randcnt = 256;
        }
        self.randcnt -= 1;
        self.randrsl[self.randcnt]
    }

    /// Generate keystream bytes. Each u64 is written as big-endian.
    /// Trailing bytes (when `len` is not a multiple of 8) take the BE prefix.
    pub fn keystream(&mut self, len: usize) -> Vec<u8> {
        let mut buf = Vec::with_capacity(len);
        let full_blocks = len / 8;

        for _ in 0..full_blocks {
            buf.extend_from_slice(&self.next_u64().to_be_bytes());
        }

        let remaining = len % 8;
        if remaining > 0 {
            let last = self.next_u64().to_be_bytes();
            buf.extend_from_slice(&last[..remaining]);
        }

        buf
    }

    fn init(&mut self) {
        const GOLDEN: u64 = 0x9e3779b97f4a7c15;
        let (mut a, mut b, mut c, mut d) = (GOLDEN, GOLDEN, GOLDEN, GOLDEN);
        let (mut e, mut f, mut g, mut h) = (GOLDEN, GOLDEN, GOLDEN, GOLDEN);

        macro_rules! mix {
            () => {
                a = a.wrapping_sub(e);
                f ^= h >> 9;
                h = h.wrapping_add(a);
                b = b.wrapping_sub(f);
                g ^= a << 9;
                a = a.wrapping_add(b);
                c = c.wrapping_sub(g);
                h ^= b >> 23;
                b = b.wrapping_add(c);
                d = d.wrapping_sub(h);
                a ^= c << 15;
                c = c.wrapping_add(d);
                e = e.wrapping_sub(a);
                b ^= d >> 14;
                d = d.wrapping_add(e);
                f = f.wrapping_sub(b);
                c ^= e << 20;
                e = e.wrapping_add(f);
                g = g.wrapping_sub(c);
                d ^= f >> 17;
                f = f.wrapping_add(g);
                h = h.wrapping_sub(d);
                e ^= g << 14;
                g = g.wrapping_add(h);
            };
        }

        // 4 rounds of mixing
        for _ in 0..4 {
            mix!();
        }

        // First pass: mix in seed material from randrsl
        for i in (0..256).step_by(8) {
            a = a.wrapping_add(self.randrsl[i]);
            b = b.wrapping_add(self.randrsl[i + 1]);
            c = c.wrapping_add(self.randrsl[i + 2]);
            d = d.wrapping_add(self.randrsl[i + 3]);
            e = e.wrapping_add(self.randrsl[i + 4]);
            f = f.wrapping_add(self.randrsl[i + 5]);
            g = g.wrapping_add(self.randrsl[i + 6]);
            h = h.wrapping_add(self.randrsl[i + 7]);
            mix!();
            self.mm[i] = a;
            self.mm[i + 1] = b;
            self.mm[i + 2] = c;
            self.mm[i + 3] = d;
            self.mm[i + 4] = e;
            self.mm[i + 5] = f;
            self.mm[i + 6] = g;
            self.mm[i + 7] = h;
        }

        // Second pass: mix in mm values
        for i in (0..256).step_by(8) {
            a = a.wrapping_add(self.mm[i]);
            b = b.wrapping_add(self.mm[i + 1]);
            c = c.wrapping_add(self.mm[i + 2]);
            d = d.wrapping_add(self.mm[i + 3]);
            e = e.wrapping_add(self.mm[i + 4]);
            f = f.wrapping_add(self.mm[i + 5]);
            g = g.wrapping_add(self.mm[i + 6]);
            h = h.wrapping_add(self.mm[i + 7]);
            mix!();
            self.mm[i] = a;
            self.mm[i + 1] = b;
            self.mm[i + 2] = c;
            self.mm[i + 3] = d;
            self.mm[i + 4] = e;
            self.mm[i + 5] = f;
            self.mm[i + 6] = g;
            self.mm[i + 7] = h;
        }

        // Generate first batch
        self.generate();
        self.randcnt = 256;
    }

    fn generate(&mut self) {
        self.cc = self.cc.wrapping_add(1);
        self.bb = self.bb.wrapping_add(self.cc);

        for i in 0..256 {
            let x = self.mm[i];
            match i & 3 {
                0 => self.aa ^= !(self.aa << 21),
                1 => self.aa ^= self.aa >> 5,
                2 => self.aa ^= self.aa << 12,
                3 => self.aa ^= self.aa >> 33,
                _ => unreachable!(),
            }
            self.aa = self.mm[(i + 128) & 255].wrapping_add(self.aa);
            let y = self.mm[((x >> 3) as usize) & 255]
                .wrapping_add(self.aa)
                .wrapping_add(self.bb);
            self.mm[i] = y;
            self.bb = self.mm[((y >> 11) as usize) & 255].wrapping_add(x);
            self.randrsl[i] = self.bb;
        }
    }
}
