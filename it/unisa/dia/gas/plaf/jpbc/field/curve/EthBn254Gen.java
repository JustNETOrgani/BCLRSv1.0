package it.unisa.dia.gas.plaf.jpbc.field.curve;

import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Point;

import java.math.BigInteger;

/**
 * Constructs the exact BN254 (alt_bn128) generator points used by the
 * Ethereum ecMul/ecPairing precompiles and by the Solidity verifier
 * contract's hardcoded g1Gen()/g2Gen()/hFixedGen().
 *
 * This must live in the it.unisa.dia.gas.plaf.jpbc.field.curve package to
 * clear the internal infinity flag when constructing an explicit
 * (non-random) point from known coordinates - JPBC does not expose a public
 * API for this.
 */
public final class EthBn254Gen {
    private EthBn254Gen() {}

    /** The fixed BN254 G1 generator: (1, 2). */
    public static CurveElement g1Generator(Field<?> g1Field) {
        CurveElement e = (CurveElement) g1Field.newElement();
        e.getX().set(BigInteger.ONE);
        e.getY().set(BigInteger.valueOf(2));
        e.infFlag = 0;
        return e;
    }

    /** The fixed BN254 G2 generator matching the Solidity contract's g2Gen(). */
    @SuppressWarnings("unchecked")
    public static CurveElement g2Generator(Field<?> g2Field) {
        CurveElement e = (CurveElement) g2Field.newElement();
        Point xElem = (Point) e.getX();
        Point yElem = (Point) e.getY();
        xElem.getX().set(new BigInteger("10857046999023057135944570762232829481370756359578518086990519993285655852781")); // X_re
        xElem.getY().set(new BigInteger("11559732032986387107991004021392285783925812861821192530917403151452391805634")); // X_im
        yElem.getX().set(new BigInteger("8495653923123431417604973247489272438418190587263600148770280649306958101930"));  // Y_re
        yElem.getY().set(new BigInteger("4082367875863433681332203403145435568316851327593401208105741076214120093531"));  // Y_im
        e.infFlag = 0;
        return e;
    }

    /**
     * H_FIXED: the second, independent G1 generator used to build the
     * per-event key-image base H_ev = H(ev,tD)*H_FIXED (see
     * BscfRSscheme.sol's deriveHEv/hFixedGen). These are the EXACT
     * coordinates hardcoded in the deployed contract's hFixedGen(), not an
     * independent hash-to-curve re-derivation from
     * GenerateHFixed.java's seed - constructing the explicit point
     * directly here guarantees byte-for-byte agreement with what's already
     * on-chain, which is what interoperability actually requires, rather
     * than depending on two independent implementations of a hash-to-curve
     * algorithm producing identical output (something this sandbox has no
     * way to verify without a working JPBC build anyway). If
     * GenerateHFixed.java is ever re-run against a freshly deployed
     * contract with a different H_FIXED, update both this method and the
     * Solidity constant together, from the same source of truth.
     */
    public static CurveElement hFixedGenerator(Field<?> g1Field) {
        CurveElement e = (CurveElement) g1Field.newElement();
        e.getX().set(new BigInteger("18578364905426123686847963464168493510202475543320800656315368226161095246754"));
        e.getY().set(new BigInteger("18092712915890995599559169202626743240368639481085399883944636861726335588495"));
        e.infFlag = 0;
        return e;
    }
}
