package bclrspaper;

import java.math.BigInteger;

/**
 * Minimal, self-contained BN254 (alt_bn128) G2 scalar multiplication.
 * No external crypto dependency: pure BigInteger arithmetic.
 *
 * Field / curve parameters match exactly what the Solidity contract's
 * g2Gen()/bn128_check_pairing() and the ecMul/ecPairing EVM precompiles use.
 */
public class Bn254G2 {

    // Base field prime q (same as q_Val in the contract)
    static final BigInteger P = new BigInteger(
        "21888242871839275222246405745257275088696311157297823662689037894645226208583");

    // Curve group order r (scalar field) — private keys/scalars live here
    static final BigInteger R = new BigInteger(
        "21888242871839275222246405745257275088548364400416034343698204186575808495617");

    // ---- Fp2 element: a + b*i, i^2 = -1 -------------------------------------
    static final class Fp2 {
        final BigInteger a, b;
        Fp2(BigInteger a, BigInteger b) { this.a = a.mod(P); this.b = b.mod(P); }
        static final Fp2 ZERO = new Fp2(BigInteger.ZERO, BigInteger.ZERO);
        static final Fp2 ONE  = new Fp2(BigInteger.ONE, BigInteger.ZERO);

        Fp2 add(Fp2 o) { return new Fp2(a.add(o.a), b.add(o.b)); }
        Fp2 sub(Fp2 o) { return new Fp2(a.subtract(o.a), b.subtract(o.b)); }
        Fp2 mul(Fp2 o) {
            BigInteger t1 = a.multiply(o.a).mod(P);
            BigInteger t2 = b.multiply(o.b).mod(P);
            BigInteger t3 = a.add(b).multiply(o.a.add(o.b)).mod(P);
            return new Fp2(t1.subtract(t2), t3.subtract(t1).subtract(t2));
        }
        Fp2 mulScalar(BigInteger k) { return new Fp2(a.multiply(k), b.multiply(k)); }
        Fp2 sq() { return mul(this); }
        Fp2 neg() { return new Fp2(a.negate(), b.negate()); }
        boolean isZero() { return a.signum() == 0 && b.signum() == 0; }
        Fp2 inv() {
            BigInteger t = a.multiply(a).add(b.multiply(b)).mod(P);
            BigInteger tInv = t.modInverse(P);
            return new Fp2(a.multiply(tInv), b.negate().multiply(tInv));
        }
        boolean eq(Fp2 o) { return a.equals(o.a) && b.equals(o.b); }
    }

    // Twist curve: Y^2 = X^3 + B_TWIST, where B_TWIST = 3 / (9+i)
    static final Fp2 B_TWIST;
    static {
        Fp2 nine_plus_i = new Fp2(BigInteger.valueOf(9), BigInteger.ONE);
        B_TWIST = new Fp2(BigInteger.valueOf(3), BigInteger.ZERO).mul(nine_plus_i.inv());
    }

    // ---- G2 point (affine); point-at-infinity represented with x=null -------
    static final class G2Point {
        final Fp2 x, y;
        final boolean infinity;
        G2Point(Fp2 x, Fp2 y) { this.x = x; this.y = y; this.infinity = false; }
        private G2Point() { this.x = null; this.y = null; this.infinity = true; }
        static final G2Point INF = new G2Point();
    }

    static boolean onCurve(G2Point p) {
        if (p.infinity) return true;
        Fp2 lhs = p.y.sq();
        Fp2 x3 = p.x.mul(p.x).mul(p.x);
        Fp2 rhs = x3.add(B_TWIST);
        return lhs.eq(rhs);
    }

    static G2Point add(G2Point p1, G2Point p2) {
        if (p1.infinity) return p2;
        if (p2.infinity) return p1;
        if (p1.x.eq(p2.x)) {
            if (p1.y.eq(p2.y)) return doubleP(p1);
            return G2Point.INF; // p1 == -p2
        }
        Fp2 lambda = p2.y.sub(p1.y).mul(p2.x.sub(p1.x).inv());
        Fp2 x3 = lambda.sq().sub(p1.x).sub(p2.x);
        Fp2 y3 = lambda.mul(p1.x.sub(x3)).sub(p1.y);
        return new G2Point(x3, y3);
    }

    static G2Point doubleP(G2Point p) {
        if (p.infinity) return p;
        Fp2 three = new Fp2(BigInteger.valueOf(3), BigInteger.ZERO);
        Fp2 two   = new Fp2(BigInteger.valueOf(2), BigInteger.ZERO);
        Fp2 lambda = three.mul(p.x.sq()).mul(two.mul(p.y).inv());
        Fp2 x3 = lambda.sq().sub(two.mul(p.x));
        Fp2 y3 = lambda.mul(p.x.sub(x3)).sub(p.y);
        return new G2Point(x3, y3);
    }

    static G2Point scalarMul(G2Point p, BigInteger k) {
        G2Point result = G2Point.INF;
        G2Point addend = p;
        BigInteger n = k.mod(R);
        while (n.signum() > 0) {
            if (n.testBit(0)) result = add(result, addend);
            addend = doubleP(addend);
            n = n.shiftRight(1);
        }
        return result;
    }

    // Standard BN254 G2 generator, same constants used by the contract's g2Gen().
    // Contract struct order is (X_im, X_re, Y_im, Y_re) i.e. imaginary coefficient first.
    static G2Point g2Gen() {
        Fp2 x = new Fp2(
            new BigInteger("10857046999023057135944570762232829481370756359578518086990519993285655852781"), // X_re
            new BigInteger("11559732032986387107991004021392285783925812861821192530917403151452391805634")  // X_im
        );
        Fp2 y = new Fp2(
            new BigInteger("8495653923123431417604973247489272438418190587263600148770280649306958101930"), // Y_re
            new BigInteger("4082367875863433681332203403145435568316851327593401208105741076214120093531")  // Y_im
        );
        return new G2Point(x, y);
    }

    public static void main(String[] args) {
        // Reproduce the same scalar s used earlier (Python demo) to prove the
        // two implementations agree bit-for-bit.
        BigInteger s = new BigInteger("13379943013243021871252925569855207345460153478805059243060357713668619572029");

        G2Point gen = g2Gen();
        System.out.println("g2Gen on curve: " + onCurve(gen));

        G2Point kgcPubKeyG2 = scalarMul(gen, s);
        System.out.println("kgcPubKeyG2 on curve: " + onCurve(kgcPubKeyG2));

        // Print in the contract's constructor order: X_im, X_re, Y_im, Y_re
        System.out.println("X_im = " + kgcPubKeyG2.x.b);
        System.out.println("X_re = " + kgcPubKeyG2.x.a);
        System.out.println("Y_im = " + kgcPubKeyG2.y.b);
        System.out.println("Y_re = " + kgcPubKeyG2.y.a);
    }
}
