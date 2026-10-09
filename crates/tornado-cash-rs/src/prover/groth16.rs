//! A Groth16 prover that consumes the websnark-format proving key produced by
//! the Tornado Cash Classic trusted setup (`tornadoProvingKey.bin`).
//!
//! File layout (all integers little-endian u32, field elements 8 x u32 LE in
//! Montgomery form):
//!
//! ```text
//! nVars nPublic domainSize pPolsA pPolsB pPointsA pPointsB1 pPointsB2 pPointsC pHExps
//! alfa1 beta1 delta1 (G1)  beta2 delta2 (G2)
//! polsA[nVars], polsB[nVars]   : u32 n, then n x (u32 row, Fr coef)
//! pointsA[nVars] pointsB1[nVars] (G1) pointsB2[nVars] (G2)
//! pointsC[nVars - nPublic - 1] (G1)  hExps[domainSize - 1] (G1)
//! ```

use crate::error::{Error, Result};
use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{BigInt, FftField, Field, PrimeField, UniformRand, Zero};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use std::str::FromStr;

pub struct ProvingKey {
    pub n_vars: usize,
    pub n_public: usize,
    pub domain_size: usize,
    alfa1: G1Affine,
    beta1: G1Affine,
    delta1: G1Affine,
    beta2: G2Affine,
    delta2: G2Affine,
    /// Sparse QAP columns: for each variable, (constraint row, coefficient).
    pols_a: Vec<Vec<(u32, Fr)>>,
    pols_b: Vec<Vec<(u32, Fr)>>,
    points_a: Vec<G1Affine>,
    points_b1: Vec<G1Affine>,
    points_b2: Vec<G2Affine>,
    points_c: Vec<G1Affine>,
    h_exps: Vec<G1Affine>,
}

struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn at(b: &'a [u8], pos: usize) -> Self {
        Reader { b, pos }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let s = self
            .b
            .get(self.pos..self.pos + n)
            .ok_or_else(|| Error::ProvingKey("unexpected end of file".into()))?;
        self.pos += n;
        Ok(s)
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn limbs(&mut self) -> Result<[u64; 4]> {
        let s = self.take(32)?;
        let mut l = [0u64; 4];
        for (i, limb) in l.iter_mut().enumerate() {
            *limb = u64::from_le_bytes(s[i * 8..i * 8 + 8].try_into().unwrap());
        }
        Ok(l)
    }
    /// Montgomery-form base field element. arkworks also stores Fq in
    /// Montgomery form with R = 2^256, so the limbs can be used directly.
    fn fq(&mut self) -> Result<Fq> {
        Ok(Fq::new_unchecked(BigInt::new(self.limbs()?)))
    }
    fn fr(&mut self) -> Result<Fr> {
        Ok(Fr::new_unchecked(BigInt::new(self.limbs()?)))
    }
    fn g1(&mut self) -> Result<G1Affine> {
        let x = self.fq()?;
        let y = self.fq()?;
        // snarkjs encodes the point at infinity as (0, 1) (or (0, 0)).
        if x.is_zero() {
            return Ok(G1Affine::zero());
        }
        let p = G1Affine::new_unchecked(x, y);
        if !p.is_on_curve() {
            return Err(Error::ProvingKey("G1 point not on curve".into()));
        }
        Ok(p)
    }
    fn g2(&mut self) -> Result<G2Affine> {
        let x = Fq2::new(self.fq()?, self.fq()?);
        let y = Fq2::new(self.fq()?, self.fq()?);
        if x.is_zero() {
            return Ok(G2Affine::zero());
        }
        let p = G2Affine::new_unchecked(x, y);
        if !p.is_on_curve() {
            return Err(Error::ProvingKey("G2 point not on curve".into()));
        }
        Ok(p)
    }
    fn pol(&mut self) -> Result<Vec<(u32, Fr)>> {
        let n = self.u32()? as usize;
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            let row = self.u32()?;
            v.push((row, self.fr()?));
        }
        Ok(v)
    }
}

impl ProvingKey {
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        let mut h = Reader::at(b, 0);
        let n_vars = h.u32()? as usize;
        let n_public = h.u32()? as usize;
        let domain_size = h.u32()? as usize;
        let p: Vec<usize> = (0..7)
            .map(|_| h.u32().map(|x| x as usize))
            .collect::<Result<_>>()?;
        let (p_pols_a, p_pols_b, p_a, p_b1, p_b2, p_c, p_h) =
            (p[0], p[1], p[2], p[3], p[4], p[5], p[6]);
        let alfa1 = h.g1()?;
        let beta1 = h.g1()?;
        let delta1 = h.g1()?;
        let beta2 = h.g2()?;
        let delta2 = h.g2()?;

        let mut r = Reader::at(b, p_pols_a);
        let pols_a = (0..n_vars).map(|_| r.pol()).collect::<Result<_>>()?;
        let mut r = Reader::at(b, p_pols_b);
        let pols_b = (0..n_vars).map(|_| r.pol()).collect::<Result<_>>()?;
        let mut r = Reader::at(b, p_a);
        let points_a = (0..n_vars).map(|_| r.g1()).collect::<Result<_>>()?;
        let mut r = Reader::at(b, p_b1);
        let points_b1 = (0..n_vars).map(|_| r.g1()).collect::<Result<_>>()?;
        let mut r = Reader::at(b, p_b2);
        let points_b2 = (0..n_vars).map(|_| r.g2()).collect::<Result<_>>()?;
        let mut r = Reader::at(b, p_c);
        let points_c = (0..n_vars - n_public - 1)
            .map(|_| r.g1())
            .collect::<Result<_>>()?;
        // H has degree at most domainSize - 2, so domainSize - 1 bases suffice;
        // the published key omits the final (unused) one.
        let n_h = (b.len().saturating_sub(p_h) / 64).min(domain_size);
        let mut r = Reader::at(b, p_h);
        let h_exps = (0..n_h).map(|_| r.g1()).collect::<Result<_>>()?;

        Ok(ProvingKey {
            n_vars,
            n_public,
            domain_size,
            alfa1,
            beta1,
            delta1,
            beta2,
            delta2,
            pols_a,
            pols_b,
            points_a,
            points_b1,
            points_b2,
            points_c,
            h_exps,
        })
    }

    /// Coefficients of H(x) = (A(x)B(x) - C(x)) / (x^n - 1).
    fn calc_h(&self, w: &[Fr]) -> Result<Vec<Fr>> {
        let n = self.domain_size;
        let mut domain = Radix2EvaluationDomain::<Fr>::new(n)
            .filter(|d| d.size() == n)
            .ok_or_else(|| Error::ProvingKey("bad domain size".into()))?;
        // The trusted setup placed constraint j at w^j where w is derived
        // from the multiplicative generator 7 (as websnark does), not from
        // arkworks' default two-adic root. Using any other root of unity
        // yields a proof that does not verify.
        let omega = Fr::from(7u64)
            .pow(Fr::TRACE)
            .pow([1u64 << (Fr::TWO_ADICITY - domain.log_size_of_group)]);
        domain.group_gen = omega;
        domain.group_gen_inv = omega.inverse().expect("root of unity is nonzero");
        let mut a = vec![Fr::zero(); n];
        let mut b = vec![Fr::zero(); n];
        for (i, wi) in w.iter().enumerate() {
            if wi.is_zero() {
                continue;
            }
            for (row, c) in &self.pols_a[i] {
                a[*row as usize] += *c * wi;
            }
            for (row, c) in &self.pols_b[i] {
                b[*row as usize] += *c * wi;
            }
        }
        // C agrees with A*B on the domain because every constraint holds.
        let c: Vec<Fr> = a.iter().zip(&b).map(|(x, y)| *x * y).collect();
        // Evaluate on the coset g*H, where Z(x) = x^n - 1 is the constant g^n - 1.
        let coset = domain
            .get_coset(Fr::GENERATOR)
            .ok_or_else(|| Error::ProvingKey("coset".into()))?;
        let to_coset = |mut v: Vec<Fr>| {
            domain.ifft_in_place(&mut v);
            coset.fft_in_place(&mut v);
            v
        };
        let a = to_coset(a);
        let b = to_coset(b);
        let c = to_coset(c);
        let z_inv = (Fr::GENERATOR.pow([n as u64]) - Fr::ONE).inverse().unwrap();
        let mut h: Vec<Fr> = (0..n).map(|i| (a[i] * b[i] - c[i]) * z_inv).collect();
        coset.ifft_in_place(&mut h);
        if !h[n - 1].is_zero() {
            return Err(Error::Witness(
                "witness does not satisfy the circuit".into(),
            ));
        }
        Ok(h)
    }

    /// Produce a Groth16 proof for a full witness `w` (`w[0] == 1`).
    pub fn prove<R: rand::RngCore>(&self, w: &[Fr], rng: &mut R) -> Result<Proof> {
        if w.len() != self.n_vars {
            return Err(Error::ProvingKey(format!(
                "witness has {} values, key expects {}",
                w.len(),
                self.n_vars
            )));
        }
        let h = self.calc_h(w)?;
        let r = Fr::rand(rng);
        let s = Fr::rand(rng);

        let msm1 = |bases: &[G1Affine], scalars: &[Fr]| -> G1Projective {
            G1Projective::msm_unchecked(bases, scalars)
        };
        let a = msm1(&self.points_a, w) + self.alfa1 + self.delta1 * r;
        let b1 = msm1(&self.points_b1, w) + self.beta1 + self.delta1 * s;
        let b2 = G2Projective::msm_unchecked(&self.points_b2, w) + self.beta2 + self.delta2 * s;
        let n_h = self.h_exps.len();
        let c = msm1(&self.points_c, &w[self.n_public + 1..])
            + msm1(&self.h_exps, &h[..n_h])
            + a * s
            + b1 * r
            - self.delta1 * (r * s);
        Ok(Proof {
            a: a.into_affine(),
            b: b2.into_affine(),
            c: c.into_affine(),
        })
    }
}

/// A Groth16 proof over BN254.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    pub a: G1Affine,
    pub b: G2Affine,
    pub c: G1Affine,
}

impl Proof {
    /// The 256-byte encoding the Tornado contracts take as `bytes _proof`:
    /// `a.x a.y b.x.c1 b.x.c0 b.y.c1 b.y.c0 c.x c.y`, each a big-endian uint256.
    pub fn to_solidity_bytes(&self) -> [u8; 256] {
        let mut out = [0u8; 256];
        let (ax, ay) = self.a.xy().unwrap_or_default();
        let (bx, by) = self.b.xy().unwrap_or_default();
        let (cx, cy) = self.c.xy().unwrap_or_default();
        let words = [ax, ay, bx.c1, bx.c0, by.c1, by.c0, cx, cy];
        for (i, f) in words.iter().enumerate() {
            let be = f.into_bigint().to_bytes_be_32();
            out[i * 32..i * 32 + 32].copy_from_slice(&be);
        }
        out
    }
}

trait ToBe32 {
    fn to_bytes_be_32(&self) -> [u8; 32];
}
impl ToBe32 for BigInt<4> {
    fn to_bytes_be_32(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, limb) in self.0.iter().enumerate() {
            out[32 - (i + 1) * 8..32 - i * 8].copy_from_slice(&limb.to_be_bytes());
        }
        out
    }
}

/// The verifying key hardcoded in the deployed Tornado Cash Classic
/// `Verifier.sol`. Proofs are checked against it before they are sent anywhere.
pub struct VerifyingKey {
    alfa1: G1Affine,
    beta2: G2Affine,
    gamma2: G2Affine,
    delta2: G2Affine,
    ic: Vec<G1Affine>,
}

fn fq(s: &str) -> Fq {
    Fq::from_str(s).expect("constant")
}
fn g1(x: &str, y: &str) -> G1Affine {
    G1Affine::new(fq(x), fq(y))
}
/// Solidity order: [x.c1, x.c0], [y.c1, y.c0].
fn g2(x1: &str, x0: &str, y1: &str, y0: &str) -> G2Affine {
    G2Affine::new(Fq2::new(fq(x0), fq(x1)), Fq2::new(fq(y0), fq(y1)))
}

impl VerifyingKey {
    pub fn tornado_classic() -> Self {
        VerifyingKey {
            alfa1: g1(
                "20692898189092739278193869274495556617788530808486270118371701516666252877969",
                "11713062878292653967971378194351968039596396853904572879488166084231740557279",
            ),
            beta2: g2(
                "12168528810181263706895252315640534818222943348193302139358377162645029937006",
                "281120578337195720357474965979947690431622127986816839208576358024608803542",
                "16129176515713072042442734839012966563817890688785805090011011570989315559913",
                "9011703453772030375124466642203641636825223906145908770308724549646909480510",
            ),
            gamma2: g2(
                "11559732032986387107991004021392285783925812861821192530917403151452391805634",
                "10857046999023057135944570762232829481370756359578518086990519993285655852781",
                "4082367875863433681332203403145435568316851327593401208105741076214120093531",
                "8495653923123431417604973247489272438418190587263600148770280649306958101930",
            ),
            delta2: g2(
                "21280594949518992153305586783242820682644996932183186320680800072133486887432",
                "150879136433974552800030963899771162647715069685890547489132178314736470662",
                "1081836006956609894549771334721413187913047383331561601606260283167615953295",
                "11434086686358152335540554643130007307617078324975981257823476472104616196090",
            ),
            ic: vec![
                g1(
                    "16225148364316337376768119297456868908427925829817748684139175309620217098814",
                    "5167268689450204162046084442581051565997733233062478317813755636162413164690",
                ),
                g1(
                    "12882377842072682264979317445365303375159828272423495088911985689463022094260",
                    "19488215856665173565526758360510125932214252767275816329232454875804474844786",
                ),
                g1(
                    "13083492661683431044045992285476184182144099829507350352128615182516530014777",
                    "602051281796153692392523702676782023472744522032670801091617246498551238913",
                ),
                g1(
                    "9732465972180335629969421513785602934706096902316483580882842789662669212890",
                    "2776526698606888434074200384264824461688198384989521091253289776235602495678",
                ),
                g1(
                    "8586364274534577154894611080234048648883781955345622578531233113180532234842",
                    "21276134929883121123323359450658320820075698490666870487450985603988214349407",
                ),
                g1(
                    "4910628533171597675018724709631788948355422829499855033965018665300386637884",
                    "20532468890024084510431799098097081600480376127870299142189696620752500664302",
                ),
                g1(
                    "15335858102289947642505450692012116222827233918185150176888641903531542034017",
                    "5311597067667671581646709998171703828965875677637292315055030353779531404812",
                ),
            ],
        }
    }

    pub fn verify(&self, proof: &Proof, public_inputs: &[Fr]) -> bool {
        if public_inputs.len() + 1 != self.ic.len() {
            return false;
        }
        let mut vk_x: G1Projective = self.ic[0].into_group();
        for (x, ic) in public_inputs.iter().zip(&self.ic[1..]) {
            vk_x += *ic * x;
        }
        // e(A, B) == e(alfa, beta) * e(vk_x, gamma) * e(C, delta)
        let lhs = Bn254::pairing(proof.a, proof.b);
        let rhs = Bn254::pairing(self.alfa1, self.beta2)
            + Bn254::pairing(vk_x.into_affine(), self.gamma2)
            + Bn254::pairing(proof.c, self.delta2);
        lhs == rhs
    }
}
