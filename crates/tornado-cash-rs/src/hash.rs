//! The two hash functions Tornado Cash Classic uses, implemented natively over
//! the BN254 scalar field:
//!
//! * the circomlib Pedersen hash on Baby Jubjub, used for the note commitment
//!   and the nullifier hash, and
//! * MiMCSponge(220 rounds), used for the Merkle tree.

use alloy::primitives::keccak256;
use ark_bn254::Fr;
use ark_ff::{BigInteger, Field, PrimeField, Zero};
use num_bigint::BigUint;
use std::str::FromStr;
use std::sync::OnceLock;

/// Parse a decimal string into a field element.
pub(crate) fn fr(s: &str) -> Fr {
    Fr::from_str(s).unwrap_or_else(|_| panic!("invalid field constant {s}"))
}

/// Interpret little-endian bytes as an integer and reduce it into the field.
pub fn fr_from_le_bytes(bytes: &[u8]) -> Fr {
    Fr::from_le_bytes_mod_order(bytes)
}

/// Interpret big-endian bytes as an integer and reduce it into the field.
pub fn fr_from_be_bytes(bytes: &[u8]) -> Fr {
    Fr::from_be_bytes_mod_order(bytes)
}

/// Big-endian 32-byte encoding, the `bytes32` form the contracts use.
pub fn fr_to_bytes32(x: &Fr) -> [u8; 32] {
    let v = x.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - v.len()..].copy_from_slice(&v);
    out
}

pub fn fr_to_decimal(x: &Fr) -> String {
    BigUint::from_bytes_be(&fr_to_bytes32(x)).to_string()
}

// ---------------------------------------------------------------------------
// Baby Jubjub and the circomlib Pedersen hash
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Point {
    x: Fr,
    y: Fr,
}

const BABYJUB_A: u64 = 168700;
const BABYJUB_D: u64 = 168696;

impl Point {
    fn identity() -> Self {
        Point {
            x: Fr::zero(),
            y: Fr::from(1u64),
        }
    }

    fn add(&self, o: &Point) -> Point {
        let a = Fr::from(BABYJUB_A);
        let d = Fr::from(BABYJUB_D);
        let x1x2 = self.x * o.x;
        let y1y2 = self.y * o.y;
        let dxy = d * x1x2 * y1y2;
        let one = Fr::from(1u64);
        let x3 = (self.x * o.y + self.y * o.x) * (one + dxy).inverse().expect("babyjub add");
        let y3 = (y1y2 - a * x1x2) * (one - dxy).inverse().expect("babyjub add");
        Point { x: x3, y: y3 }
    }

    fn mul(&self, scalar: &BigUint) -> Point {
        let mut acc = Point::identity();
        let mut base = *self;
        for i in 0..scalar.bits() {
            if scalar.bit(i) {
                acc = acc.add(&base);
            }
            base = base.add(&base);
        }
        acc
    }
}

/// Pedersen generators, already multiplied by the cofactor. These are the
/// `BASE` constants hardcoded in circomlib's `pedersen.circom`, which is what
/// the Tornado withdraw circuit was compiled against.
const PEDERSEN_BASES: [(&str, &str); 10] = [
    (
        "10457101036533406547632367118273992217979173478358440826365724437999023779287",
        "19824078218392094440610104313265183977899662750282163392862422243483260492317",
    ),
    (
        "2671756056509184035029146175565761955751135805354291559563293617232983272177",
        "2663205510731142763556352975002641716101654201788071096152948830924149045094",
    ),
    (
        "5802099305472655231388284418920769829666717045250560929368476121199858275951",
        "5980429700218124965372158798884772646841287887664001482443826541541529227896",
    ),
    (
        "7107336197374528537877327281242680114152313102022415488494307685842428166594",
        "2857869773864086953506483169737724679646433914307247183624878062391496185654",
    ),
    (
        "20265828622013100949498132415626198973119240347465898028410217039057588424236",
        "1160461593266035632937973507065134938065359936056410650153315956301179689506",
    ),
    (
        "1487999857809287756929114517587739322941449154962237464737694709326309567994",
        "14017256862867289575056460215526364897734808720610101650676790868051368668003",
    ),
    (
        "14618644331049802168996997831720384953259095788558646464435263343433563860015",
        "13115243279999696210147231297848654998887864576952244320558158620692603342236",
    ),
    (
        "6814338563135591367010655964669793483652536871717891893032616415581401894627",
        "13660303521961041205824633772157003587453809761793065294055279768121314853695",
    ),
    (
        "3571615583211663069428808372184817973703476260057504149923239576077102575715",
        "11981351099832644138306422070127357074117642951423551606012551622164230222506",
    ),
    (
        "18597552580465440374022635246985743886550544261632147935254624835147509493269",
        "6753322320275422086923032033899357299485124665258735666995435957890214041481",
    ),
];

const BABYJUB_SUBORDER: &str =
    "2736030358979909402780800718157159386076813972158567259200215660948447373041";

fn pedersen_base(i: usize) -> Point {
    let (x, y) = PEDERSEN_BASES[i];
    Point { x: fr(x), y: fr(y) }
}

/// circomlib `pedersenHash(msg)` followed by `unpackPoint(..)[0]`: the x
/// coordinate of the resulting Baby Jubjub point. Bits are taken least
/// significant first from each byte.
pub fn pedersen_hash(msg: &[u8]) -> Fr {
    const WINDOW: usize = 4;
    const WINDOWS_PER_SEGMENT: usize = 50;
    const BITS_PER_SEGMENT: usize = WINDOW * WINDOWS_PER_SEGMENT;

    let bits: Vec<bool> = msg
        .iter()
        .flat_map(|b| (0..8).map(move |i| (b >> i) & 1 == 1))
        .collect();
    assert!(!bits.is_empty(), "pedersen hash of empty message");
    let n_segments = (bits.len() - 1) / BITS_PER_SEGMENT + 1;
    assert!(n_segments <= PEDERSEN_BASES.len(), "message too long");

    let suborder = BigUint::from_str(BABYJUB_SUBORDER).unwrap();
    let mut acc = Point::identity();
    for s in 0..n_segments {
        let n_windows = if s == n_segments - 1 {
            ((bits.len() - (n_segments - 1) * BITS_PER_SEGMENT) - 1) / WINDOW + 1
        } else {
            WINDOWS_PER_SEGMENT
        };
        // Signed accumulation: each window contributes (1 + b0 + 2 b1 + 4 b2) * (-1)^b3.
        let mut pos = BigUint::from(0u32);
        let mut neg = BigUint::from(0u32);
        let mut exp = BigUint::from(1u32);
        for w in 0..n_windows {
            let mut o = s * BITS_PER_SEGMENT + w * WINDOW;
            let mut v: u32 = 1;
            let mut b = 0;
            while b < WINDOW - 1 && o < bits.len() {
                if bits[o] {
                    v += 1 << b;
                }
                o += 1;
                b += 1;
            }
            let mut negative = false;
            if o < bits.len() {
                negative = bits[o];
            }
            let term = &exp * v;
            if negative {
                neg += term;
            } else {
                pos += term;
            }
            exp <<= WINDOW + 1;
        }
        let scalar = if pos >= neg {
            pos - neg
        } else {
            // escalar < 0 => subOrder + escalar
            let d = neg - pos;
            (&suborder - (&d % &suborder)) % &suborder
        };
        acc = acc.add(&pedersen_base(s).mul(&scalar));
    }
    acc.x
}

// ---------------------------------------------------------------------------
// MiMCSponge
// ---------------------------------------------------------------------------

const MIMC_ROUNDS: usize = 220;

fn mimc_constants() -> &'static [Fr; MIMC_ROUNDS] {
    static C: OnceLock<[Fr; MIMC_ROUNDS]> = OnceLock::new();
    C.get_or_init(|| {
        let mut out = [Fr::zero(); MIMC_ROUNDS];
        let mut c = keccak256(b"mimcsponge");
        for slot in out.iter_mut().take(MIMC_ROUNDS - 1).skip(1) {
            c = keccak256(c.as_slice());
            *slot = fr_from_be_bytes(c.as_slice());
        }
        // c[0] and c[219] are zero by definition.
        out
    })
}

/// One MiMC Feistel permutation with key `k`.
pub fn mimc_feistel(mut xl: Fr, mut xr: Fr, k: Fr) -> (Fr, Fr) {
    let c = mimc_constants();
    for (i, ci) in c.iter().enumerate() {
        let t = xl + k + ci;
        let t2 = t.square();
        let t5 = t2.square() * t;
        if i < MIMC_ROUNDS - 1 {
            let tmp = xr + t5;
            xr = xl;
            xl = tmp;
        } else {
            xr += t5;
        }
    }
    (xl, xr)
}

/// The Merkle tree node hash: `MiMCSponge([left, right], k = 0)`.
pub fn hash_left_right(left: Fr, right: Fr) -> Fr {
    let (r, c) = mimc_feistel(left, Fr::zero(), Fr::zero());
    let (r, _) = mimc_feistel(r + right, c, Fr::zero());
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merkle_zero_values_match_contract() {
        // MerkleTreeWithHistory.zeros(0) and zeros(1) from tornado-core.
        let z0 = fr_from_be_bytes(keccak256(b"tornado").as_slice());
        assert_eq!(
            hex::encode(fr_to_bytes32(&z0)),
            "2fe54c60d3acabf3343a35b6eba15db4821b340f76e741e2249685ed4899af6c"
        );
        let z1 = hash_left_right(z0, z0);
        assert_eq!(
            hex::encode(fr_to_bytes32(&z1)),
            "256a6135777eee2fd26f54b8b7037a25439d5235caee224154186d2b8a52e31d"
        );
    }
}
