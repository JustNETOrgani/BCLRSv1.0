package bclrspaper;

import java.math.BigInteger;

public class BN256Compat {
    public static final BigInteger P = new BigInteger("21888242871839275222246405745257275088696311157297823662689037894645226208583");

    public static BigInteger reduceToField(BigInteger value) {
        return value.mod(P);
    }

    public static String toSolidityUint(BigInteger value) {
        return reduceToField(value).toString();
    }

    public static String toSolidityPoint(BigInteger x, BigInteger y) {
        return "G1Point(" + toSolidityUint(x) + ", " + toSolidityUint(y) + ")";
    }
}
