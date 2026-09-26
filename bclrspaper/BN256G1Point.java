package bclrspaper;

import java.math.BigInteger;

public class BN256G1Point {
    private static final BigInteger P = BN256Compat.P;
    private static final BigInteger TWO = BigInteger.valueOf(2);
    private static final BigInteger THREE = BigInteger.valueOf(3);
    // Standard BN256 / alt_bn128 G1 generator point.
    public static final BN256G1Point GENERATOR = new BN256G1Point(
            BigInteger.ONE,
            new BigInteger("2")
    );

    private final BigInteger x;
    private final BigInteger y;
    private final boolean infinity;

    public BN256G1Point(BigInteger x, BigInteger y) {
        this(x, y, false);
    }

    private BN256G1Point(BigInteger x, BigInteger y, boolean infinity) {
        this.x = x;
        this.y = y;
        this.infinity = infinity;
    }

    public static BN256G1Point infinity() {
        return new BN256G1Point(null, null, true);
    }

    public static BN256G1Point scalarMultiply(BigInteger scalar) {
        return GENERATOR.multiply(scalar);
    }

    public BN256G1Point multiply(BigInteger scalar) {
        if (scalar == null || scalar.signum() == 0) {
            return infinity();
        }

        BN256G1Point result = infinity();
        BN256G1Point addend = this;
        BigInteger n = scalar.abs();

        while (n.signum() > 0) {
            if (n.testBit(0)) {
                result = result.add(addend);
            }
            addend = addend.add(addend);
            n = n.shiftRight(1);
        }

        if (scalar.signum() < 0) {
            result = result.negate();
        }
        return result;
    }

    public BN256G1Point negate() {
        if (isInfinity()) {
            return this;
        }
        return new BN256G1Point(this.x, P.subtract(this.y));
    }

    public BN256G1Point add(BN256G1Point other) {
        if (this.isInfinity()) {
            return other;
        }
        if (other.isInfinity()) {
            return this;
        }

        if (this.x.equals(other.x)) {
            if (this.y.equals(other.y.negate().mod(P))) {
                return infinity();
            }
            if (this.y.equals(other.y)) {
                BigInteger lambda = THREE.multiply(this.x.modPow(BigInteger.valueOf(2), P))
                        .multiply(TWO.multiply(this.y).modInverse(P))
                        .mod(P);
                return pointFromSlope(this.x, this.y, lambda);
            }
        }

        BigInteger lambda = other.y.subtract(this.y).mod(P)
                .multiply(other.x.subtract(this.x).mod(P).modInverse(P))
                .mod(P);
        return pointFromSlope(this.x, this.y, lambda, other.x, other.y);
    }

    public boolean isOnCurve() {
        if (this.isInfinity()) {
            return true;
        }
        BigInteger lhs = this.y.modPow(BigInteger.valueOf(2), P);
        BigInteger rhs = this.x.modPow(BigInteger.valueOf(3), P).add(THREE).mod(P);
        return lhs.equals(rhs);
    }

    public BigInteger getX() {
        return x;
    }

    public BigInteger getY() {
        return y;
    }

    public boolean isInfinity() {
        return infinity;
    }

    public String toSolidityString() {
        return "G1Point(" + BN256Compat.toSolidityUint(x) + ", " + BN256Compat.toSolidityUint(y) + ")";
    }

    private static BN256G1Point pointFromSlope(BigInteger x1, BigInteger y1, BigInteger lambda) {
        BigInteger x3 = lambda.modPow(BigInteger.valueOf(2), P).subtract(x1).subtract(x1).mod(P);
        BigInteger y3 = lambda.multiply(x1.subtract(x3)).subtract(y1).mod(P);
        return new BN256G1Point(x3, y3);
    }

    private static BN256G1Point pointFromSlope(BigInteger x1, BigInteger y1, BigInteger lambda, BigInteger x2, BigInteger y2) {
        BigInteger x3 = lambda.modPow(BigInteger.valueOf(2), P).subtract(x1).subtract(x2).mod(P);
        BigInteger y3 = lambda.multiply(x1.subtract(x3)).subtract(y1).mod(P);
        return new BN256G1Point(x3, y3);
    }
}
