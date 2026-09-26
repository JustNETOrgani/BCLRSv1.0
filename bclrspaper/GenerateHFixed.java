package bclrspaper;

import it.unisa.dia.gas.jpbc.Element;

/**
 * One-off utility: computes H_FIXED, the nothing-up-my-sleeve G1 generator
 * with unknown discrete log relative to g1Gen(), used to build the
 * per-event key-image base H_ev = H(ev,T_D)*H_FIXED
 * "Implementation remark: instantiating H_ev safely"; CryptoContext.initialize()).
 *
 * It is run ONCE, whenever JPBC is available. It prints H_FIXED in Solidity
 * literal form and used in the SC's hFixedGen().
 *
 * The seed string (CryptoContext.H_FIXED_SEED) is fixed and never
 * changes: anyone can rerun this exact program against that string and get
 * the identical point back, which is what makes H_FIXED's "nothing up my
 * sleeve" status independently auditable by any third party, rather than
 * merely asserted by whoever originally ran it. Public verifiability.
 */
public class GenerateHFixed {
    public static void main(String[] args) throws CryptoException {
        CryptoContext context = new CryptoContext();
        context.initialize();

        Element hFixed = context.getCryptoParams().H_FIXED;
        @SuppressWarnings("unchecked")
        it.unisa.dia.gas.jpbc.Point<Element> p = (it.unisa.dia.gas.jpbc.Point<Element>) hFixed;

        System.out.println("Seed string: \"" + CryptoContext.H_FIXED_SEED + "\"");
        System.out.println("H_FIXED.X = " + p.getX());
        System.out.println("H_FIXED.Y = " + p.getY());
        System.out.println();
        System.out.println("Paste into bcscfRS_ring.sol's hFixedGen(), replacing the PLACEHOLDER values:");
        System.out.println("    return G1Point(" + p.getX() + ", " + p.getY() + ");");
    }
}
