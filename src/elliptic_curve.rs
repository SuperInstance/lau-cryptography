use num_bigint::{BigInt, BigUint, ToBigInt, ToBigUint};
use num_traits::{One, Zero, Signed};
use serde::{Deserialize, Serialize};

/// A point on an elliptic curve (or the point at infinity)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EcPoint {
    pub x: Option<String>, // hex, None = point at infinity
    pub y: Option<String>,
}

impl EcPoint {
    pub fn new(x: BigUint, y: BigUint) -> Self {
        EcPoint {
            x: Some(format!("{:x}", x)),
            y: Some(format!("{:x}", y)),
        }
    }

    pub fn infinity() -> Self {
        EcPoint { x: None, y: None }
    }

    pub fn is_infinity(&self) -> bool {
        self.x.is_none()
    }

    pub fn x(&self) -> Option<BigUint> {
        self.x.as_ref().map(|s| BigUint::parse_bytes(s.as_bytes(), 16).unwrap())
    }

    pub fn y(&self) -> Option<BigUint> {
        self.y.as_ref().map(|s| BigUint::parse_bytes(s.as_bytes(), 16).unwrap())
    }
}

/// Elliptic curve over a finite field: y^2 = x^3 + ax + b (mod p)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EllipticCurve {
    pub a: String, // hex
    pub b: String, // hex
    pub p: String, // prime modulus, hex
    pub n: String, // order of the base point, hex
    pub g: EcPoint, // base point
}

impl EllipticCurve {
    /// Create a new elliptic curve y^2 = x^3 + ax + b (mod p)
    pub fn new(a: BigUint, b: BigUint, p: BigUint, n: BigUint, g: EcPoint) -> Self {
        EllipticCurve {
            a: format!("{:x}", a),
            b: format!("{:x}", b),
            p: format!("{:x}", p),
            n: format!("{:x}", n),
            g,
        }
    }

    /// Create the secp256k1-like curve (educational, smaller)
    pub fn secp256k1_small() -> Self {
        // Small curve for testing: y^2 = x^3 + 7 mod p
        let p = BigUint::parse_bytes(
            b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
            16,
        ).unwrap();
        let a = BigUint::zero();
        let b = BigUint::parse_bytes(b"7", 10).unwrap();
        let n = p.clone();

        // Generator point for secp256k1
        let gx = BigUint::parse_bytes(
            b"79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
            16,
        ).unwrap();
        let gy = BigUint::parse_bytes(
            b"483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
            16,
        ).unwrap();

        EllipticCurve::new(a, b, p, n, EcPoint::new(gx, gy))
    }

    fn get_a(&self) -> BigUint {
        BigUint::parse_bytes(self.a.as_bytes(), 16).unwrap()
    }

    fn get_b(&self) -> BigUint {
        BigUint::parse_bytes(self.b.as_bytes(), 16).unwrap()
    }

    fn get_p(&self) -> BigUint {
        BigUint::parse_bytes(self.p.as_bytes(), 16).unwrap()
    }

    fn get_n(&self) -> BigUint {
        BigUint::parse_bytes(self.n.as_bytes(), 16).unwrap()
    }

    /// Check if a point is on this curve
    pub fn is_on_curve(&self, point: &EcPoint) -> bool {
        if point.is_infinity() {
            return true;
        }
        let x = match point.x() {
            Some(x) => x.to_bigint().unwrap(),
            None => return true,
        };
        let y = match point.y() {
            Some(y) => y.to_bigint().unwrap(),
            None => return false,
        };

        let p = self.get_p().to_bigint().unwrap();
        let a = self.get_a().to_bigint().unwrap();
        let b = self.get_b().to_bigint().unwrap();

        // y^2 mod p == (x^3 + ax + b) mod p
        let lhs = (&y * &y) % &p;
        let rhs = (&x * &x * &x + &a * &x + b) % &p;
        let lhs = if lhs.is_negative() { &lhs + &p } else { lhs };
        let rhs = if rhs.is_negative() { &rhs + &p } else { rhs };
        lhs == rhs
    }

    /// Point addition: P + Q
    pub fn point_add(&self, p1: &EcPoint, p2: &EcPoint) -> EcPoint {
        if p1.is_infinity() {
            return p2.clone();
        }
        if p2.is_infinity() {
            return p1.clone();
        }

        let p = self.get_p().to_bigint().unwrap();
        let a = self.get_a().to_bigint().unwrap();
        let zero = BigInt::zero();

        let x1 = p1.x().unwrap().to_bigint().unwrap();
        let y1 = p1.y().unwrap().to_bigint().unwrap();
        let x2 = p2.x().unwrap().to_bigint().unwrap();
        let y2 = p2.y().unwrap().to_bigint().unwrap();

        let slope = if x1 == x2 {
            if y1 != y2 {
                // P + (-P) = O
                return EcPoint::infinity();
            }
            // Point doubling: slope = (3x1^2 + a) / (2y1) mod p
            let num = (BigInt::from(3) * &x1 * &x1 + &a) % &p;
            let num = if num.is_negative() { &num + &p } else { num };
            let den = (BigInt::from(2) * &y1) % &p;
            let den = if den.is_negative() { &den + &p } else { den };
            let den_inv = mod_inverse_bigint(&den, &p);
            (num * den_inv) % &p
        } else {
            // slope = (y2 - y1) / (x2 - x1) mod p
            let num = (&y2 - &y1) % &p;
            let num = if num.is_negative() { &num + &p } else { num };
            let den = (&x2 - &x1) % &p;
            let den = if den.is_negative() { &den + &p } else { den };
            if den == zero {
                return EcPoint::infinity();
            }
            let den_inv = mod_inverse_bigint(&den, &p);
            (num * den_inv) % &p
        };

        let slope = if slope.is_negative() { &slope + &p } else { slope };

        // x3 = slope^2 - x1 - x2 mod p
        let x3 = (&slope * &slope - &x1 - &x2) % &p;
        let x3 = if x3.is_negative() { &x3 + &p } else { x3 };
        // y3 = slope * (x1 - x3) - y1 mod p
        let y3 = (slope * (&x1 - &x3) - y1) % &p;
        let y3 = if y3.is_negative() { &y3 + &p } else { y3 };

        EcPoint::new(x3.to_biguint().unwrap(), y3.to_biguint().unwrap())
    }

    /// Scalar multiplication: k * P using double-and-add
    pub fn scalar_multiply(&self, k: &BigUint, point: &EcPoint) -> EcPoint {
        if k == &BigUint::zero() || point.is_infinity() {
            return EcPoint::infinity();
        }

        let mut result = EcPoint::infinity();
        let mut addend = point.clone();
        let mut k = k.clone();

        while k > BigUint::zero() {
            if k.bit(0) {
                result = self.point_add(&result, &addend);
            }
            addend = self.point_add(&addend, &addend);
            k >>= 1;
        }

        result
    }

    /// Point negation: -P
    pub fn point_negate(&self, point: &EcPoint) -> EcPoint {
        if point.is_infinity() {
            return EcPoint::infinity();
        }
        let x = point.x().unwrap();
        let y = point.y().unwrap();
        let p = self.get_p();
        EcPoint::new(x.clone(), &p - &y)
    }

    /// Generate a key pair on this curve
    pub fn generate_keypair(&self) -> (BigUint, EcPoint) {
        use rand::rngs::OsRng;
        use num_bigint::RandBigInt;

        let n = self.get_n();
        let two = 2u32.to_biguint().unwrap();
        let mut rng = OsRng;
        let private_key = rng.gen_biguint_range(&two, &n);
        let public_key = self.scalar_multiply(&private_key, &self.g);
        (private_key, public_key)
    }
}

fn mod_inverse_bigint(a: &BigInt, m: &BigInt) -> BigInt {
    let mut old_r = a.clone();
    let mut r = m.clone();
    let mut old_s = BigInt::one();
    let mut s = BigInt::zero();

    while r > BigInt::zero() {
        let quotient = &old_r / &r;
        let tmp_r = r.clone();
        r = &old_r - &quotient * &r;
        old_r = tmp_r;
        let tmp_s = s.clone();
        s = &old_s - &quotient * &s;
        old_s = tmp_s;
    }

    if old_s.is_negative() {
        &old_s + m
    } else {
        old_s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn small_curve() -> EllipticCurve {
        // y^2 = x^3 + 2x + 3 mod 97
        let a = BigUint::from(2u32);
        let b = BigUint::from(3u32);
        let p = BigUint::from(97u32);
        let n = BigUint::from(100u32); // approximate order
        // Point (3, 6) is on this curve: 36 mod 97 = 27+6+3 = 36 mod 97 ✓
        let g = EcPoint::new(BigUint::from(3u32), BigUint::from(6u32));
        EllipticCurve::new(a, b, p, n, g)
    }

    #[test]
    fn test_point_on_curve() {
        let curve = small_curve();
        assert!(curve.is_on_curve(&curve.g));
    }

    #[test]
    fn test_point_not_on_curve() {
        let curve = small_curve();
        let bad_point = EcPoint::new(BigUint::from(3u32), BigUint::from(7u32));
        assert!(!curve.is_on_curve(&bad_point));
    }

    #[test]
    fn test_point_addition() {
        let curve = small_curve();
        let g = &curve.g;
        let p2 = curve.point_add(g, g);
        assert!(curve.is_on_curve(&p2));
    }

    #[test]
    fn test_point_add_identity() {
        let curve = small_curve();
        let g = &curve.g;
        let inf = EcPoint::infinity();
        let result = curve.point_add(g, &inf);
        assert_eq!(result, *g);
    }

    #[test]
    fn test_scalar_multiply_one() {
        let curve = small_curve();
        let g = &curve.g;
        let result = curve.scalar_multiply(&BigUint::one(), g);
        assert_eq!(result, *g);
    }

    #[test]
    fn test_scalar_multiply() {
        let curve = small_curve();
        let g = &curve.g;
        let result = curve.scalar_multiply(&BigUint::from(5u32), g);
        assert!(curve.is_on_curve(&result));
        // Verify 5*G == G+G+G+G+G
        let mut expected = g.clone();
        for _ in 0..4 {
            expected = curve.point_add(&expected, g);
        }
        assert_eq!(result, expected);
    }

    #[test]
    fn test_point_negate() {
        let curve = small_curve();
        let g = &curve.g;
        let neg_g = curve.point_negate(g);
        assert!(curve.is_on_curve(&neg_g));

        // P + (-P) = O
        let result = curve.point_add(g, &neg_g);
        assert!(result.is_infinity());
    }

    #[test]
    fn test_infinity_on_curve() {
        let curve = small_curve();
        assert!(curve.is_on_curve(&EcPoint::infinity()));
    }

    #[test]
    fn test_scalar_multiply_zero() {
        let curve = small_curve();
        let g = &curve.g;
        let result = curve.scalar_multiply(&BigUint::zero(), g);
        assert!(result.is_infinity());
    }

    #[test]
    fn test_ec_keypair_generation() {
        let curve = small_curve();
        let (private_key, public_key) = curve.generate_keypair();
        assert!(private_key > BigUint::zero());
        assert!(curve.is_on_curve(&public_key));
    }
}
