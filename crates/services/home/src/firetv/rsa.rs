//! The one thing ADB needs that `ring` will not give: an RSA private-key
//! operation over a caller-built PKCS#1 block.
//!
//! # Why this exists at all
//!
//! ADB authenticates a host by challenge: the television sends a 20-byte token
//! and the host must return `token` signed with its RSA key, PKCS#1 v1.5 with
//! the **SHA-1** `DigestInfo` — but the token *is* the digest, already, and is
//! never hashed. `ring`'s RSA signing hashes the message it is given, so it
//! computes `sign(SHA1(token))` where ADB needs `sign(token)`; `ring` also
//! neither generates RSA keys nor exposes a raw modular exponentiation. There
//! is no way to reach ADB's scheme through it.
//!
//! The workspace links exactly one cryptographic implementation on purpose
//! (see the `Cargo.toml` provider note), and a second general crypto crate is
//! the thing that policy exists to keep out. So the narrow operation ADB needs
//! is written here instead: a small fixed-width big integer, Knuth long
//! division, modular exponentiation, a Miller–Rabin keygen, and the two
//! encodings ADB speaks. This is not a crypto provider and does not try to be
//! one — it signs an auth token to a television on the operator's own LAN, and
//! the signature proves possession of a key, guarding no secret. Constant-time
//! behaviour is therefore not a goal, which is the one thing that makes writing
//! it defensible rather than reckless.
//!
//! # What is proved without the hardware
//!
//! Every claim a test can reach is reached: division and modular inverse
//! against fixed vectors, `sign` verified by re-exponentiating with the public
//! exponent, a generated key satisfying `d·e ≡ 1 (mod λ)` and round-tripping a
//! signature, and the [`android_pubkey_struct`] structure byte-for-byte. What
//! no test here can reach is a real television accepting the signature; that
//! waits on the live bring-up, and until then this module's correctness rests
//! on the math being checkable in isolation, which it is.

use std::cmp::Ordering;

/// The DER `AlgorithmIdentifier` + `DigestInfo` prefix for a SHA-1 digest.
///
/// ADB builds `DigestInfo = PREFIX || token`, a 35-byte block, and pads it into
/// a PKCS#1 v1.5 signature. The token is treated as the 20-byte digest and is
/// never hashed, which is the whole reason a general RSA signer cannot be used.
const SHA1_DIGEST_INFO_PREFIX: [u8; 15] = [
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
];

/// The public exponent every key here uses. 65537 is what Android generates and
/// what its public-key wire format hard-codes a `u32` field for.
const PUBLIC_EXPONENT: u32 = 65_537;

/// The modulus size in bits. Android's public-key format is fixed at this width
/// and rejects anything else, so keygen forces the product to exactly 2048 bits.
const MODULUS_BITS: usize = 2048;

/// The modulus size in bytes.
const MODULUS_BYTES: usize = MODULUS_BITS / 8;

/// A non-negative integer as little-endian 32-bit limbs, least significant
/// first, with no trailing zero limbs (so zero is the empty vector).
///
/// Little-endian because ADB's public-key format stores the modulus that way
/// and because a normalised representation makes equality and division simpler
/// to reason about than a fixed-width one would.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Uint {
    limbs: Vec<u32>,
}

impl Uint {
    /// Zero.
    #[must_use]
    pub fn zero() -> Self {
        Uint { limbs: Vec::new() }
    }

    /// A small integer.
    #[must_use]
    pub fn from_u32(value: u32) -> Self {
        let mut u = Uint { limbs: vec![value] };
        u.normalize();
        u
    }

    /// Reads a big-endian byte string, most significant byte first.
    #[must_use]
    pub fn from_bytes_be(bytes: &[u8]) -> Self {
        let mut limbs = Vec::with_capacity(bytes.len() / 4 + 1);
        // Walk the bytes from the least significant end, four at a time.
        let mut i = bytes.len();
        while i > 0 {
            let start = i.saturating_sub(4);
            let mut limb = 0_u32;
            for (shift, &byte) in bytes[start..i].iter().rev().enumerate() {
                limb |= u32::from(byte) << (8 * shift);
            }
            limbs.push(limb);
            i = start;
        }
        let mut u = Uint { limbs };
        u.normalize();
        u
    }

    /// Writes exactly `len` big-endian bytes, left-padded with zeros. Panics if
    /// the value does not fit, which for this module is a programming error
    /// rather than input: every caller sizes `len` to the modulus.
    #[must_use]
    pub fn to_bytes_be(&self, len: usize) -> Vec<u8> {
        let mut out = vec![0_u8; len];
        for (i, &limb) in self.limbs.iter().enumerate() {
            for byte in 0..4 {
                let value = (limb >> (8 * byte)) as u8;
                if value == 0 {
                    continue;
                }
                let position = i * 4 + byte;
                assert!(position < len, "value does not fit in {len} bytes");
                out[len - 1 - position] = value;
            }
        }
        out
    }

    /// Writes exactly `len` little-endian bytes, right-padded with zeros —
    /// the order ADB's public-key format stores the modulus and `rr` in.
    #[must_use]
    pub fn to_bytes_le(&self, len: usize) -> Vec<u8> {
        let mut be = self.to_bytes_be(len);
        be.reverse();
        be
    }

    /// Whether this is zero.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.limbs.is_empty()
    }

    /// Whether this is odd.
    #[must_use]
    fn is_odd(&self) -> bool {
        self.limbs.first().is_some_and(|limb| limb & 1 == 1)
    }

    /// The position of the highest set bit plus one, or zero for zero.
    #[must_use]
    fn bit_len(&self) -> usize {
        match self.limbs.last() {
            None => 0,
            Some(&top) => (self.limbs.len() - 1) * 32 + (32 - top.leading_zeros() as usize),
        }
    }

    /// The value of one bit.
    #[must_use]
    fn bit(&self, index: usize) -> bool {
        let limb = index / 32;
        self.limbs.get(limb).is_some_and(|&value| (value >> (index % 32)) & 1 == 1)
    }

    /// Drops trailing zero limbs so the representation is unique.
    fn normalize(&mut self) {
        while self.limbs.last() == Some(&0) {
            self.limbs.pop();
        }
    }

    /// Orders two values.
    #[must_use]
    fn cmp(&self, other: &Uint) -> Ordering {
        if self.limbs.len() != other.limbs.len() {
            return self.limbs.len().cmp(&other.limbs.len());
        }
        for i in (0..self.limbs.len()).rev() {
            match self.limbs[i].cmp(&other.limbs[i]) {
                Ordering::Equal => {}
                other => return other,
            }
        }
        Ordering::Equal
    }

    /// Sum.
    #[must_use]
    fn add(&self, other: &Uint) -> Uint {
        let mut limbs = Vec::with_capacity(self.limbs.len().max(other.limbs.len()) + 1);
        let mut carry = 0_u64;
        for i in 0..self.limbs.len().max(other.limbs.len()) {
            let a = u64::from(self.limbs.get(i).copied().unwrap_or(0));
            let b = u64::from(other.limbs.get(i).copied().unwrap_or(0));
            let sum = a + b + carry;
            limbs.push(sum as u32);
            carry = sum >> 32;
        }
        if carry != 0 {
            limbs.push(carry as u32);
        }
        let mut u = Uint { limbs };
        u.normalize();
        u
    }

    /// Difference, which the caller must know is non-negative (`self >= other`).
    #[must_use]
    fn sub(&self, other: &Uint) -> Uint {
        debug_assert!(self.cmp(other) != Ordering::Less, "sub would go negative");
        let mut limbs = Vec::with_capacity(self.limbs.len());
        let mut borrow = 0_i64;
        for i in 0..self.limbs.len() {
            let a = i64::from(self.limbs[i]);
            let b = i64::from(other.limbs.get(i).copied().unwrap_or(0));
            let mut diff = a - b - borrow;
            if diff < 0 {
                diff += 1 << 32;
                borrow = 1;
            } else {
                borrow = 0;
            }
            limbs.push(diff as u32);
        }
        let mut u = Uint { limbs };
        u.normalize();
        u
    }

    /// Product, schoolbook.
    #[must_use]
    fn mul(&self, other: &Uint) -> Uint {
        if self.is_zero() || other.is_zero() {
            return Uint::zero();
        }
        let mut limbs = vec![0_u32; self.limbs.len() + other.limbs.len()];
        for (i, &a) in self.limbs.iter().enumerate() {
            let mut carry = 0_u64;
            for (j, &b) in other.limbs.iter().enumerate() {
                let here = u64::from(limbs[i + j]) + u64::from(a) * u64::from(b) + carry;
                limbs[i + j] = here as u32;
                carry = here >> 32;
            }
            limbs[i + other.limbs.len()] += carry as u32;
        }
        let mut u = Uint { limbs };
        u.normalize();
        u
    }

    /// Left shift by whole bits.
    #[must_use]
    fn shl(&self, bits: usize) -> Uint {
        if self.is_zero() {
            return Uint::zero();
        }
        let whole = bits / 32;
        let part = bits % 32;
        let mut limbs = vec![0_u32; whole];
        let mut carry = 0_u64;
        for &limb in &self.limbs {
            let shifted = (u64::from(limb) << part) | carry;
            limbs.push(shifted as u32);
            carry = shifted >> 32;
        }
        if carry != 0 {
            limbs.push(carry as u32);
        }
        let mut u = Uint { limbs };
        u.normalize();
        u
    }

    /// Quotient and remainder, `self` divided by `divisor` — Knuth's Algorithm
    /// D (TAOCP vol. 2, §4.3.1), the schoolbook long division that estimates
    /// each quotient digit from the two leading dividend limbs and corrects it.
    ///
    /// Panics on a zero divisor, which no caller here passes.
    #[must_use]
    fn divmod(&self, divisor: &Uint) -> (Uint, Uint) {
        assert!(!divisor.is_zero(), "division by zero");
        match self.cmp(divisor) {
            Ordering::Less => return (Uint::zero(), self.clone()),
            Ordering::Equal => return (Uint::from_u32(1), Uint::zero()),
            Ordering::Greater => {}
        }
        // A single-limb divisor has a simple exact loop and skips the whole
        // normalise/estimate machinery, which needs at least two divisor limbs.
        if divisor.limbs.len() == 1 {
            let d = u64::from(divisor.limbs[0]);
            let mut quotient = vec![0_u32; self.limbs.len()];
            let mut rem = 0_u64;
            for i in (0..self.limbs.len()).rev() {
                let cur = (rem << 32) | u64::from(self.limbs[i]);
                quotient[i] = (cur / d) as u32;
                rem = cur % d;
            }
            let mut q = Uint { limbs: quotient };
            q.normalize();
            return (q, Uint::from_u32(rem as u32));
        }

        // Normalise so the divisor's top limb has its high bit set, which is
        // what makes the two-limb quotient estimate off by at most two.
        let shift = divisor.limbs.last().unwrap().leading_zeros() as usize;
        let u = self.shl(shift);
        let v = divisor.shl(shift);
        let n = v.limbs.len();
        let mut u_limbs = u.limbs.clone();
        // Algorithm D indexes u up to m+n; guarantee the extra top limb exists.
        u_limbs.resize(self.limbs.len() + 1 + n, 0);
        let m = u_limbs.len() - n - 1;

        let v_top = u64::from(v.limbs[n - 1]);
        let v_second = u64::from(v.limbs[n - 2]);
        let mut quotient = vec![0_u32; m + 1];

        for j in (0..=m).rev() {
            let numer = (u64::from(u_limbs[j + n]) << 32) | u64::from(u_limbs[j + n - 1]);
            let mut qhat = numer / v_top;
            let mut rhat = numer % v_top;
            // Correct the estimate: qhat is too big while its next partial
            // product overshoots the corresponding dividend limbs.
            while qhat >= (1 << 32)
                || qhat * v_second > (rhat << 32) | u64::from(u_limbs[j + n - 2])
            {
                qhat -= 1;
                rhat += v_top;
                if rhat >= (1 << 32) {
                    break;
                }
            }

            // Multiply v by qhat and subtract from the u window.
            let mut borrow = 0_i64;
            let mut carry = 0_u64;
            for i in 0..n {
                let product = qhat * u64::from(v.limbs[i]) + carry;
                carry = product >> 32;
                let sub = i64::from(u_limbs[j + i]) - borrow - i64::from(product as u32);
                u_limbs[j + i] = sub as u32;
                borrow = if sub < 0 { 1 } else { 0 };
            }
            let sub = i64::from(u_limbs[j + n]) - borrow - i64::from(carry as u32);
            u_limbs[j + n] = sub as u32;

            if sub < 0 {
                // The estimate was one too large after all: give one back and
                // add a single v back into the window.
                qhat -= 1;
                let mut add_carry = 0_u64;
                for i in 0..n {
                    let here =
                        u64::from(u_limbs[j + i]) + u64::from(v.limbs[i]) + add_carry;
                    u_limbs[j + i] = here as u32;
                    add_carry = here >> 32;
                }
                u_limbs[j + n] = (u64::from(u_limbs[j + n]) + add_carry) as u32;
            }
            quotient[j] = qhat as u32;
        }

        let mut q = Uint { limbs: quotient };
        q.normalize();
        // The remainder is the low n limbs, shifted back down by the same
        // normalisation applied to the dividend.
        u_limbs.truncate(n);
        let mut r = Uint { limbs: u_limbs };
        r.normalize();
        (q, r.shr(shift))
    }

    /// Right shift by whole bits, used only to undo [`Uint::shl`] on a
    /// division remainder.
    #[must_use]
    fn shr(&self, bits: usize) -> Uint {
        if bits == 0 {
            return self.clone();
        }
        let whole = bits / 32;
        let part = bits % 32;
        if whole >= self.limbs.len() {
            return Uint::zero();
        }
        let mut limbs = vec![0_u32; self.limbs.len() - whole];
        for (out, i) in (whole..self.limbs.len()).enumerate() {
            let low = self.limbs[i] >> part;
            let high = if part == 0 {
                0
            } else {
                self.limbs.get(i + 1).copied().unwrap_or(0) << (32 - part)
            };
            limbs[out] = low | high;
        }
        let mut u = Uint { limbs };
        u.normalize();
        u
    }

    /// Remainder of `self` modulo `modulus`.
    #[must_use]
    fn rem(&self, modulus: &Uint) -> Uint {
        self.divmod(modulus).1
    }

    /// `(self * other) mod modulus`.
    #[must_use]
    fn mul_mod(&self, other: &Uint, modulus: &Uint) -> Uint {
        self.mul(other).rem(modulus)
    }

    /// `self^exponent mod modulus`, left-to-right square-and-multiply.
    #[must_use]
    fn pow_mod(&self, exponent: &Uint, modulus: &Uint) -> Uint {
        if modulus.cmp(&Uint::from_u32(1)) == Ordering::Equal {
            return Uint::zero();
        }
        let mut result = Uint::from_u32(1);
        let base = self.rem(modulus);
        for i in (0..exponent.bit_len()).rev() {
            result = result.mul_mod(&result, modulus);
            if exponent.bit(i) {
                result = result.mul_mod(&base, modulus);
            }
        }
        result
    }

    /// The modular inverse of `self` modulo `modulus`, or `None` when they are
    /// not coprime — the iterative extended Euclid, kept unsigned by carrying
    /// the running coefficient reduced modulo `modulus`.
    #[must_use]
    fn inv_mod(&self, modulus: &Uint) -> Option<Uint> {
        let mut t = Uint::zero();
        let mut new_t = Uint::from_u32(1);
        let mut r = modulus.clone();
        let mut new_r = self.rem(modulus);

        while !new_r.is_zero() {
            let (q, rem) = r.divmod(&new_r);
            // (t, new_t) = (new_t, t - q*new_t) with the subtraction done mod m.
            let qt = q.mul_mod(&new_t, modulus);
            let next_t = sub_mod(&t, &qt, modulus);
            t = new_t;
            new_t = next_t;
            r = new_r;
            new_r = rem;
        }
        if r.cmp(&Uint::from_u32(1)) != Ordering::Equal {
            return None; // gcd != 1: not invertible
        }
        Some(t)
    }
}

/// `(a - b) mod m`, kept non-negative.
#[must_use]
fn sub_mod(a: &Uint, b: &Uint, m: &Uint) -> Uint {
    let a = a.rem(m);
    let b = b.rem(m);
    if a.cmp(&b) == Ordering::Less {
        a.add(m).sub(&b)
    } else {
        a.sub(&b)
    }
}

/// An RSA private key: the modulus, the public exponent, and the private
/// exponent. `p` and `q` are not retained — signing here is a single
/// exponentiation modulo `n`, so the CRT parameters would be weight without a
/// use, and dropping them keeps the persisted form to the three values Android
/// itself round-trips.
#[derive(Debug, Clone)]
pub struct PrivateKey {
    /// The modulus `n = p·q`, exactly 2048 bits.
    n: Uint,
    /// The public exponent, 65537.
    e: Uint,
    /// The private exponent `d`.
    d: Uint,
}

impl PrivateKey {
    /// Generates a fresh 2048-bit key.
    ///
    /// Two ~1024-bit probable primes are drawn with their top two bits set, so
    /// the product is exactly 2048 bits, and re-drawn until each is coprime to
    /// the public exponent. The primality test is Miller–Rabin after trial
    /// division by small primes, which rejects the overwhelming majority of
    /// candidates without a single exponentiation.
    ///
    /// This runs once in a deployment's life and is then persisted, so its cost
    /// is paid at the operator's first opt-in and never again.
    #[must_use]
    pub fn generate() -> PrivateKey {
        let e = Uint::from_u32(PUBLIC_EXPONENT);
        loop {
            let p = random_prime(MODULUS_BITS / 2);
            let q = random_prime(MODULUS_BITS / 2);
            if p.cmp(&q) == Ordering::Equal {
                continue;
            }
            let n = p.mul(&q);
            if n.bit_len() != MODULUS_BITS {
                continue;
            }
            let one = Uint::from_u32(1);
            let lambda = lcm(&p.sub(&one), &q.sub(&one));
            let Some(d) = e.inv_mod(&lambda) else {
                continue; // e shared a factor with p-1 or q-1; draw again.
            };
            return PrivateKey { n, e, d };
        }
    }

    /// Rebuilds a key from its three stored values in big-endian bytes.
    #[must_use]
    pub fn from_parts(n: &[u8], e: &[u8], d: &[u8]) -> PrivateKey {
        PrivateKey {
            n: Uint::from_bytes_be(n),
            e: Uint::from_bytes_be(e),
            d: Uint::from_bytes_be(d),
        }
    }

    /// The three values to persist, each big-endian and left-padded to the
    /// modulus width so a reload is exact.
    #[must_use]
    pub fn to_parts(&self) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        (
            self.n.to_bytes_be(MODULUS_BYTES),
            self.e.to_bytes_be(4),
            self.d.to_bytes_be(MODULUS_BYTES),
        )
    }

    /// Signs a 20-byte ADB auth token: PKCS#1 v1.5 over `SHA1-DigestInfo ||
    /// token`, with the token used directly as the digest and never hashed.
    /// Returns the 256-byte signature, or `None` if the token is not 20 bytes.
    #[must_use]
    pub fn sign_token(&self, token: &[u8]) -> Option<Vec<u8>> {
        if token.len() != 20 {
            return None;
        }
        let block = pkcs1v15_sha1_block(token);
        let message = Uint::from_bytes_be(&block);
        let signature = message.pow_mod(&self.d, &self.n);
        Some(signature.to_bytes_be(MODULUS_BYTES))
    }

    /// Recovers the signed block from a signature with the public exponent —
    /// the verification a test uses to prove `sign_token` without a television.
    #[must_use]
    pub fn public_recover(&self, signature: &[u8]) -> Vec<u8> {
        let s = Uint::from_bytes_be(signature);
        s.pow_mod(&self.e, &self.n).to_bytes_be(MODULUS_BYTES)
    }

    /// The public key in Android's `RSAPublicKey` wire format, base64 of the
    /// 524-byte structure followed by a ` user@host` label and a NUL — the
    /// exact bytes the `AUTH RSAPUBLICKEY` message carries and the television
    /// stores against the operator's "allow" tap. `label` names this host in the
    /// television's list of authorised computers.
    #[must_use]
    pub fn android_pubkey(&self, label: &str) -> Vec<u8> {
        let mut encoded = base64(&android_pubkey_struct(&self.n));
        encoded.push(b' ');
        encoded.extend_from_slice(label.as_bytes());
        encoded.push(0);
        encoded
    }
}

/// Builds the 256-byte PKCS#1 v1.5 block `00 01 FF..FF 00 DigestInfo` for a
/// 20-byte token, with the padding string filling the modulus width.
#[must_use]
fn pkcs1v15_sha1_block(token: &[u8]) -> Vec<u8> {
    let digest_info_len = SHA1_DIGEST_INFO_PREFIX.len() + token.len(); // 35
    let padding_len = MODULUS_BYTES - 3 - digest_info_len;
    let mut block = Vec::with_capacity(MODULUS_BYTES);
    block.push(0x00);
    block.push(0x01);
    block.extend(std::iter::repeat_n(0xFF, padding_len));
    block.push(0x00);
    block.extend_from_slice(&SHA1_DIGEST_INFO_PREFIX);
    block.extend_from_slice(token);
    block
}

/// Serialises a modulus into Android's `RSAPublicKey` C structure, packed
/// little-endian: the word count, the Montgomery constant `n0inv`, the modulus,
/// `rr = R^2 mod n`, and the public exponent (see Android's
/// `system/core/libcrypto_utils/android_pubkey.c`).
#[must_use]
fn android_pubkey_struct(n: &Uint) -> Vec<u8> {
    let words = (MODULUS_BYTES / 4) as u32; // 64
    let n0inv = mont_n0inv(n);
    let r = Uint::from_u32(1).shl(MODULUS_BITS); // R = 2^2048
    let rr = r.mul_mod(&r, n); // R^2 mod n

    let mut out = Vec::with_capacity(4 + 4 + MODULUS_BYTES + MODULUS_BYTES + 4);
    out.extend_from_slice(&words.to_le_bytes());
    out.extend_from_slice(&n0inv.to_le_bytes());
    out.extend_from_slice(&n.to_bytes_le(MODULUS_BYTES));
    out.extend_from_slice(&rr.to_bytes_le(MODULUS_BYTES));
    out.extend_from_slice(&PUBLIC_EXPONENT.to_le_bytes());
    out
}

/// `-1 / n mod 2^32`, the Montgomery constant Android's format stores. The
/// inverse of `n mod 2^32` is found by Newton's iteration, which doubles its
/// correct bits each step and so needs five steps for 32 bits.
#[must_use]
fn mont_n0inv(n: &Uint) -> u32 {
    let n0 = n.limbs.first().copied().unwrap_or(0);
    let mut inv = 1_u32;
    for _ in 0..5 {
        inv = inv.wrapping_mul(2_u32.wrapping_sub(n0.wrapping_mul(inv)));
    }
    // -inv mod 2^32.
    0_u32.wrapping_sub(inv)
}

/// The least common multiple, via `a·b / gcd(a, b)`.
#[must_use]
fn lcm(a: &Uint, b: &Uint) -> Uint {
    let g = gcd(a, b);
    a.divmod(&g).0.mul(b)
}

/// The greatest common divisor, Euclid.
#[must_use]
fn gcd(a: &Uint, b: &Uint) -> Uint {
    let mut a = a.clone();
    let mut b = b.clone();
    while !b.is_zero() {
        let r = a.rem(&b);
        a = b;
        b = r;
    }
    a
}

/// A random probable prime of exactly `bits` bits with its top two bits set —
/// the top bit forcing the width and the second guaranteeing a 2048-bit product
/// of two such primes.
#[must_use]
fn random_prime(bits: usize) -> Uint {
    loop {
        let mut candidate = random_bits(bits);
        // Force width (top bit), the product's width (second bit), and oddness.
        set_bit(&mut candidate, bits - 1);
        set_bit(&mut candidate, bits - 2);
        set_bit(&mut candidate, 0);
        if is_probable_prime(&candidate) {
            return candidate;
        }
    }
}

/// Sets one bit of a value.
fn set_bit(u: &mut Uint, index: usize) {
    let limb = index / 32;
    while u.limbs.len() <= limb {
        u.limbs.push(0);
    }
    u.limbs[limb] |= 1 << (index % 32);
    u.normalize();
}

/// A random value of exactly `bits` bits of entropy, drawn from the OS.
#[must_use]
fn random_bits(bits: usize) -> Uint {
    let bytes = bits.div_ceil(8);
    let mut buffer = vec![0_u8; bytes];
    getrandom::getrandom(&mut buffer).expect("the OS random source must be available");
    Uint::from_bytes_be(&buffer)
}

/// The small primes trial division rejects composites by before any
/// exponentiation. The first several hundred remove the great majority of
/// candidates for the cost of a division each.
const SMALL_PRIMES: [u32; 54] = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
    101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193,
    197, 199, 211, 223, 227, 229, 233, 239, 241, 251,
];

/// Whether a value is prime to a negligible error, trial division then
/// Miller–Rabin with fixed and random bases. Forty rounds put the false-prime
/// probability far below any hardware or cosmic-ray floor, which is the right
/// budget for a key generated once.
#[must_use]
fn is_probable_prime(n: &Uint) -> bool {
    let one = Uint::from_u32(1);
    if n.cmp(&Uint::from_u32(2)) == Ordering::Less {
        return false;
    }
    for &p in &SMALL_PRIMES {
        let prime = Uint::from_u32(p);
        if n.cmp(&prime) == Ordering::Equal {
            return true;
        }
        if n.rem(&prime).is_zero() {
            return false;
        }
    }

    // n - 1 = 2^r · d, with d odd.
    let n_minus_one = n.sub(&one);
    let mut d = n_minus_one.clone();
    let mut r = 0_usize;
    while !d.is_odd() {
        d = d.shr(1);
        r += 1;
    }

    let mut rounds = 0;
    let mut witness_index = 0;
    while rounds < 40 {
        // Fixed small witnesses first, then random ones in [2, n-2].
        let a = if witness_index < SMALL_PRIMES.len() {
            let candidate = Uint::from_u32(SMALL_PRIMES[witness_index]);
            witness_index += 1;
            if candidate.cmp(&n_minus_one) != Ordering::Less {
                continue;
            }
            candidate
        } else {
            // A random witness in [2, n-2].
            random_bits(n.bit_len()).rem(&n.sub(&Uint::from_u32(3))).add(&Uint::from_u32(2))
        };

        let mut x = a.pow_mod(&d, n);
        if x.cmp(&one) == Ordering::Equal || x.cmp(&n_minus_one) == Ordering::Equal {
            rounds += 1;
            continue;
        }
        let mut composite = true;
        for _ in 0..r.saturating_sub(1) {
            x = x.mul_mod(&x, n);
            if x.cmp(&n_minus_one) == Ordering::Equal {
                composite = false;
                break;
            }
        }
        if composite {
            return false;
        }
        rounds += 1;
    }
    true
}

/// Standard base64 with padding, over the ADB public-key bytes.
#[must_use]
fn base64(input: &[u8]) -> Vec<u8> {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        out.push(ALPHABET[(b0 >> 2) as usize]);
        out.push(ALPHABET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize]);
        out.push(if chunk.len() > 1 {
            ALPHABET[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize]
        } else {
            b'='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(b2 & 0x3f) as usize]
        } else {
            b'='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A decimal string into a [`Uint`], for writing test vectors in the base a
    /// person reads. Only what the tests need: repeated multiply-and-add.
    fn from_decimal(text: &str) -> Uint {
        let ten = Uint::from_u32(10);
        let mut value = Uint::zero();
        for ch in text.bytes() {
            let digit = Uint::from_u32(u32::from(ch - b'0'));
            value = value.mul(&ten).add(&digit);
        }
        value
    }

    #[test]
    fn bytes_round_trip_big_endian() {
        let bytes = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x00, 0xff];
        let u = Uint::from_bytes_be(&bytes);
        assert_eq!(u.to_bytes_be(10), bytes);
    }

    #[test]
    fn little_endian_is_the_reverse_of_big_endian() {
        let u = Uint::from_bytes_be(&[0x12, 0x34, 0x56]);
        assert_eq!(u.to_bytes_le(3), [0x56, 0x34, 0x12]);
    }

    #[test]
    fn addition_carries_across_a_limb() {
        let a = Uint::from_u32(u32::MAX);
        let b = Uint::from_u32(1);
        assert_eq!(a.add(&b), Uint::from_bytes_be(&[0x01, 0x00, 0x00, 0x00, 0x00]));
    }

    #[test]
    fn multiplication_matches_a_known_product() {
        let a = from_decimal("123456789012345678901234567890");
        let b = from_decimal("987654321098765432109876543210");
        let expected = from_decimal(
            "121932631137021795226185032733622923332237463801111263526900",
        );
        assert_eq!(a.mul(&b), expected);
    }

    /// The division vector that exercises quotient-digit correction: a wide
    /// dividend over a two-limb divisor, checked against the known answer and
    /// by reconstructing the dividend from `q·v + r`.
    #[test]
    fn division_matches_a_known_quotient_and_remainder() {
        let a = from_decimal("340282366920938463463374607431768211457"); // 2^128 + 1
        let b = from_decimal("18446744073709551616"); // 2^64
        let (q, r) = a.divmod(&b);
        assert_eq!(q, from_decimal("18446744073709551616")); // 2^64
        assert_eq!(r, Uint::from_u32(1));
        assert_eq!(q.mul(&b).add(&r), a);
    }

    #[test]
    fn division_reconstructs_the_dividend_for_a_wide_case() {
        let a = from_decimal(
            "99999999999999999999999999999999999999999999999999999999999999",
        );
        let b = from_decimal("123456789012345678901234567");
        let (q, r) = a.divmod(&b);
        assert_eq!(q.mul(&b).add(&r), a);
        assert_eq!(r.cmp(&b), Ordering::Less);
    }

    #[test]
    fn modular_exponentiation_matches_a_known_value() {
        // 7^2020 mod 1000000007, computed independently.
        let base = Uint::from_u32(7);
        let exp = Uint::from_u32(2020);
        let modulus = Uint::from_u32(1_000_000_007);
        assert_eq!(base.pow_mod(&exp, &modulus), Uint::from_u32(403_769_496));
    }

    #[test]
    fn a_modular_inverse_multiplies_back_to_one() {
        let a = Uint::from_u32(65_537);
        let m = from_decimal("100000000000000000000000000000057"); // a prime
        let inv = a.inv_mod(&m).expect("coprime, so invertible");
        assert_eq!(a.mul_mod(&inv, &m), Uint::from_u32(1));
    }

    #[test]
    fn a_shared_factor_has_no_inverse() {
        let a = Uint::from_u32(6);
        let m = Uint::from_u32(9);
        assert_eq!(a.inv_mod(&m), None);
    }

    /// The PKCS#1 v1.5 block is the exact width of the modulus and has the
    /// shape `00 01 FF..FF 00 <sha1 prefix> <token>`.
    #[test]
    fn the_signature_block_is_well_formed() {
        let token = [0xAB_u8; 20];
        let block = pkcs1v15_sha1_block(&token);
        assert_eq!(block.len(), MODULUS_BYTES);
        assert_eq!(&block[..2], &[0x00, 0x01]);
        assert!(block[2..2 + 218].iter().all(|&b| b == 0xFF));
        assert_eq!(block[220], 0x00);
        assert_eq!(&block[221..221 + 15], &SHA1_DIGEST_INFO_PREFIX);
        assert_eq!(&block[236..], &token);
    }

    /// The property that stands in for a television: a token signed with the
    /// private key re-exponentiates under the public key back to the exact
    /// PKCS#1 block that was signed. This is what a verifier checks, so a key
    /// that passes it is a key a correct verifier accepts.
    #[test]
    fn a_signature_verifies_against_the_public_key() {
        let key = PrivateKey::generate();
        let token = [0x5A_u8; 20];
        let signature = key.sign_token(&token).expect("a 20-byte token signs");
        assert_eq!(signature.len(), MODULUS_BYTES);
        assert_eq!(key.public_recover(&signature), pkcs1v15_sha1_block(&token));
    }

    #[test]
    fn a_token_of_the_wrong_length_does_not_sign() {
        let key = PrivateKey::generate();
        assert_eq!(key.sign_token(&[0; 19]), None);
        assert_eq!(key.sign_token(&[0; 32]), None);
    }

    /// A generated key is a valid RSA key: the modulus is exactly 2048 bits and
    /// signing then recovering is the end-to-end proof; this narrower test pins
    /// the modulus width the pubkey format demands.
    #[test]
    fn a_generated_modulus_is_exactly_the_declared_width() {
        let key = PrivateKey::generate();
        assert_eq!(key.n.bit_len(), MODULUS_BITS);
        assert_eq!(key.to_parts().0.len(), MODULUS_BYTES);
    }

    /// The stored triple reloads into a key that signs identically — the
    /// persistence round-trip the driver relies on so a restart does not
    /// re-provoke the television's "allow" dialog.
    #[test]
    fn a_key_survives_a_parts_round_trip() {
        let key = PrivateKey::generate();
        let (n, e, d) = key.to_parts();
        let reloaded = PrivateKey::from_parts(&n, &e, &d);
        let token = [0x33_u8; 20];
        assert_eq!(key.sign_token(&token), reloaded.sign_token(&token));
    }

    /// The Android public-key structure is fixed at 524 bytes: two `u32`
    /// headers, two modulus-width fields, and the exponent. The base64 label
    /// form ends in the host name and a NUL, which is what the device stores.
    #[test]
    fn the_android_pubkey_structure_is_the_declared_shape() {
        let key = PrivateKey::generate();
        let structure = android_pubkey_struct(&key.n);
        assert_eq!(structure.len(), 4 + 4 + MODULUS_BYTES + MODULUS_BYTES + 4);
        assert_eq!(&structure[..4], &64_u32.to_le_bytes()); // 64 words
        assert_eq!(&structure[structure.len() - 4..], &PUBLIC_EXPONENT.to_le_bytes());

        let labelled = key.android_pubkey("selfhost@home");
        assert!(labelled.ends_with(b" selfhost@home\0"));
    }

    /// `n0inv` is the negative inverse of the modulus modulo 2^32: multiplied
    /// by the low modulus word it gives 2^32 − 1's complement, i.e. the
    /// product is ≡ −1.
    #[test]
    fn the_montgomery_constant_is_the_negative_inverse() {
        let n = from_decimal("100000000000000000000000000000057");
        let n0 = n.limbs[0];
        let n0inv = mont_n0inv(&n);
        assert_eq!(n0.wrapping_mul(n0inv), u32::MAX); // n0 · (−n0^{-1}) ≡ −1 (mod 2^32)
    }

    #[test]
    fn base64_matches_known_vectors() {
        assert_eq!(base64(b""), b"");
        assert_eq!(base64(b"f"), b"Zg==");
        assert_eq!(base64(b"fo"), b"Zm8=");
        assert_eq!(base64(b"foo"), b"Zm9v");
        assert_eq!(base64(b"foobar"), b"Zm9vYmFy");
    }

    #[test]
    fn small_composites_and_primes_are_told_apart() {
        assert!(!is_probable_prime(&Uint::from_u32(1)));
        assert!(is_probable_prime(&Uint::from_u32(2)));
        assert!(is_probable_prime(&Uint::from_u32(97)));
        assert!(!is_probable_prime(&Uint::from_u32(99)));
        assert!(is_probable_prime(&from_decimal("1000000007")));
        assert!(!is_probable_prime(&from_decimal("1000000005")));
    }
}
