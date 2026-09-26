package bclrspaper;

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;

import bclrspaper.model.periodKeyPackage;
import bclrspaper.model.signatureVals;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Point;

/**
 * THis implements the ring signature algorithm.
 */
public class RingSignatureService {
    private final CryptoContext context;
    private final HashingService hashingService;

    public RingSignatureService(CryptoContext context, HashingService hashingService) {
        this.context = context;
        this.hashingService = hashingService;
    }

    /**
     * @param piIndex   index of the signer within L / ringUID (0-based)
     * @param ringUID   U_ID_i for every member of L, in the SAME order as L
     *                  (already-registered public values - publicly available,
     *                  no secret needed for any slot except piIndex)
     */
    public ArrayList<signatureVals> ringSign(
            String ev, String[] L, int piIndex, periodKeyPackage ek, Element u_s, String msg, int T_D,
            Element[] ringUID) throws CryptoException {

        signatureVals sigmaVal = new signatureVals();

        // KGC-binding pair, A_s side. t_p/sk are purely
        // off-chain constructs.
        Element t_p = context.getCryptoParams().Zr.newElement();
        String prepTpHash = Integer.toString(T_D);
        hashingService.hash(t_p, prepTpHash);
        Element r_s = context.getCryptoParams().Zr.newRandomElement();
        Element A_s = ek.getAtilde().duplicate().mulZn(r_s.duplicate());
        sigmaVal.setA_s(A_s);

        int n = L.length;
        byte[] userListEncoding = encodeUserList(L);

        // --- key image: I = u_pi * H_ev --- 
        Element H_ev = deriveHEv(ev, T_D);
        Element I = H_ev.duplicate().mulZn(u_s);
        sigmaVal.setKeyImage(I);

        // --- h_As = H6(msg || A_s), deterministic ---
        Element h_As = deriveHAs(msg, A_s);

        // --- h' = H(msg,ev,L,T_D,I,h_As), via abi.encode ---
        Element hAsPrime = deriveHAsPrime(msg, ev, userListEncoding, T_D, I, h_As);
        sigmaVal.setB_s(ek.getSkTD().mulZn(r_s.mulZn(hAsPrime.invert())));

        // --- c = H(I,L,ev,T_D); combined base g1+c*H_ev and the additive
        // term c*I reused for every decoy slot's target. ---
        Element c = deriveC(I, userListEncoding, ev, T_D);
        Element combinedBase = context.getCryptoParams().G.duplicate().add(H_ev.duplicate().mulZn(c));
        Element cI = I.duplicate().mulZn(c);

        // --- ring-membership OR-proof over the combined base/target,
        // AOS-style, canonicalized so eStart = e[0] regardless of where
        // the real signer pi actually sits. ---
        Element[] e = new Element[n];
        Element[] z = new Element[n];

        Element k = context.getCryptoParams().Zr.newRandomElement();
        Element T_pi = combinedBase.duplicate().mulZn(k);

        int nextIdx = (piIndex + 1) % n;
        Element eNext = chainChallenge(sigmaVal, h_As, userListEncoding, msg, ev, T_D, piIndex, T_pi);
        e[nextIdx] = eNext;

        int idx = nextIdx;
        while (idx != piIndex) {
            Element z_i = context.getCryptoParams().Zr.newRandomElement();
            z[idx] = z_i;
            Element target_i = ringUID[idx].duplicate().add(cI);
            Element T_i = combinedBase.duplicate().mulZn(z_i).sub(target_i.duplicate().mulZn(e[idx]));
            eNext = chainChallenge(sigmaVal, h_As, userListEncoding, msg, ev, T_D, idx, T_i);
            idx = (idx + 1) % n;
            e[idx] = eNext;
        }
        // close the loop with the real witness u_s
        z[piIndex] = k.add(e[piIndex].duplicate().mulZn(u_s));

        // Canonicalize the published starting challenge to slot 0 (well-defined
        // after a full cycle, regardless of where pi actually is) so the
        // verifier never needs to know pi to know where to start walking.
        Element eStart = e[0];

        sigmaVal.setEStart(eStart);
        sigmaVal.setZ(z);

        ArrayList<signatureVals> sigmaS = new ArrayList<>();
        sigmaS.add(sigmaVal);
        return sigmaS;
    }

    /**
     * @param ringUID U_ID_i for every member of L, in the SAME order as L
     *                (as registered/stored on-chain - public data)
     */
    public boolean ringVerify(ArrayList<signatureVals> sigmaS, String[] L, String msg, String ev, int T_D, Element[] ringUID) throws CryptoException {
        signatureVals sig = sigmaS.get(0);
        int n = L.length;
        byte[] userListEncoding = encodeUserList(L);

        // --- h_As = H6(msg || A_s), recomputed by the verifier rather
        // than read off the signature ---
        Element h_As = deriveHAs(msg, sig.getA_s());

        // --- check 1: KGC-binding pairing check (mirrors
        // the Smart contract's ringVerify/ringVerifyCore) ---
        Element hAsPrime = deriveHAsPrime(msg, ev, userListEncoding, T_D, sig.getKeyImage(), h_As);

        Element lhs = context.getCryptoParams().pairing.pairing(sig.getB_s().duplicate(), context.getCryptoParams().G2gen.duplicate());
        Element rhsCompute = sig.getA_s().duplicate().mulZn(hAsPrime.duplicate().invert()).getImmutable();
        Element rhs = context.getCryptoParams().pairing.pairing(rhsCompute.duplicate(), context.getMasterPublicKeyG2().duplicate());
        boolean check1 = lhs.isEqual(rhs);

        // --- check 2: ring-membership OR-proof chain closure over the
        // combined base/target (mirrors checkRingMembership/chainStep) ---
        Element c = deriveC(sig.getKeyImage(), userListEncoding, ev, T_D);
        Element H_ev = deriveHEv(ev, T_D);
        Element combinedBase = context.getCryptoParams().G.duplicate().add(H_ev.duplicate().mulZn(c));
        Element cI = sig.getKeyImage().duplicate().mulZn(c);

        Element eCur = sig.getEStart();
        for (int idx = 0; idx < n; idx++) {
            Element target_i = ringUID[idx].duplicate().add(cI);
            Element T_i = combinedBase.duplicate().mulZn(sig.getZ()[idx]).sub(target_i.duplicate().mulZn(eCur));
            eCur = chainChallenge(sig, h_As, userListEncoding, msg, ev, T_D, idx, T_i);
        }
        boolean check2 = eCur.isEqual(sig.getEStart());

        return check1 && check2;
    }

    /**
     * Two signatures under the same event context (ev,T_D) were produced
     * by the same signer iff their key images are equal - this does
     * not itself re-verify either signature, it only compares the already-
     * bound key images but can easiliy be extended to do so if desired.
     */
    public static boolean link(signatureVals sigA, signatureVals sigB) {
        return sigA.getKeyImage().isEqual(sigB.getKeyImage());
    }

    // -------------------------------------------------------------------
    // Hash-preimage helpers - all five mirror SC's
    // abi.encode-based functions of the same name. Every uint256 argument
    // goes through AbiEncoder.u(BigInteger); every string through
    // AbiEncoder.s(String); every already-ABI-encoded blob (userListEncoding,
    // and now sigEncoding below) through AbiEncoder.b(byte[]) - matching
    // the Solidity side's argument types position-for-position is what
    // makes the two sides hash the same preimage.
    // -------------------------------------------------------------------

    /** Mirrors BscfRSscheme.sol's encodeUserList: abi.encode(userList). */
    private byte[] encodeUserList(String[] L) throws CryptoException {
        try {
            return AbiEncoder.encode(AbiEncoder.sArr(L));
        } catch (IOException ex) {
            throw new CryptoException("Failed to ABI-encode ring member list", ex);
        }
    }

    /** Mirrors SC's deriveHEv: H(ev,tD) reduced to a Zr
     * scalar, then H_FIXED*scalar. */
    private Element deriveHEv(String ev, int T_D) throws CryptoException {
        byte[] preimage;
        try {
            preimage = AbiEncoder.encode(AbiEncoder.s(ev), AbiEncoder.u(BigInteger.valueOf(T_D)));
        } catch (IOException ex) {
            throw new CryptoException("Failed to ABI-encode deriveHEv preimage", ex);
        }
        Element scalar = context.getCryptoParams().Zr.newElement();
        hashingService.hash(scalar, preimage);
        return context.getCryptoParams().H_FIXED.duplicate().mulZn(scalar);
    }

    /** Mirrors the SC's deriveC: H(I.X, I.Y, userListEncoding, ev, tD). */
    private Element deriveC(Element keyImage, byte[] userListEncoding, String ev, int T_D) throws CryptoException {
        byte[] preimage;
        try {
            preimage = AbiEncoder.encode(
                    AbiEncoder.u(coordX(keyImage)), AbiEncoder.u(coordY(keyImage)),
                    AbiEncoder.b(userListEncoding), AbiEncoder.s(ev), AbiEncoder.u(BigInteger.valueOf(T_D))
            );
        } catch (IOException ex) {
            throw new CryptoException("Failed to ABI-encode deriveC preimage", ex);
        }
        Element out = context.getCryptoParams().Zr.newElement();
        hashingService.hash(out, preimage);
        return out;
    }

    /**
     * h_As = H6(message || A_s) - deterministic, mirrors the SC's
     * deriveHAs. both sides derive the identical value from data that's already public.
     */
    private Element deriveHAs(String msg, Element A_s) throws CryptoException {
        byte[] preimage;
        try {
            preimage = AbiEncoder.encode(AbiEncoder.s(msg), AbiEncoder.u(coordX(A_s)), AbiEncoder.u(coordY(A_s)));
        } catch (IOException ex) {
            throw new CryptoException("Failed to ABI-encode deriveHAs preimage", ex);
        }
        Element out = context.getCryptoParams().Zr.newElement();
        hashingService.hash(out, preimage);
        return out;
    }

    /** Mirrors the SC's deriveHAsPrime: H(message, ev,
     * userListEncoding, tD, sigKeyImage.X, sigKeyImage.Y, hAs).
     * The parameter is renamed from the previous h_As to hAs purely to make that distinction
     * visible at the call site. */
    private Element deriveHAsPrime(String msg, String ev, byte[] userListEncoding, int T_D, Element keyImage, Element hAs) throws CryptoException {
        byte[] preimage;
        try {
            preimage = AbiEncoder.encode(
                    AbiEncoder.s(msg), AbiEncoder.s(ev), AbiEncoder.b(userListEncoding), AbiEncoder.u(BigInteger.valueOf(T_D)),
                    AbiEncoder.u(coordX(keyImage)), AbiEncoder.u(coordY(keyImage)), AbiEncoder.u(toBigInt(hAs))
            );
        } catch (IOException ex) {
            throw new CryptoException("Failed to ABI-encode deriveHAsPrime preimage", ex);
        }
        Element out = context.getCryptoParams().Zr.newElement();
        hashingService.hash(out, preimage);
        return out;
    }

    /**
     * Mirrors the SC's deriveChainChallenge.
     */
    private Element chainChallenge(signatureVals sig, Element hAs, byte[] userListEncoding, String msg, String ev, int T_D,
                                    int idx, Element T_i) throws CryptoException {
        byte[] sigEncoding;
        byte[] preimage;
        try {
            sigEncoding = AbiEncoder.encode(
                    AbiEncoder.u(coordX(sig.getA_s())), AbiEncoder.u(coordY(sig.getA_s())),
                    AbiEncoder.u(coordX(sig.getB_s())), AbiEncoder.u(coordY(sig.getB_s())),
                    AbiEncoder.u(coordX(sig.getKeyImage())), AbiEncoder.u(coordY(sig.getKeyImage())),
                    AbiEncoder.u(toBigInt(hAs))
            );
            preimage = AbiEncoder.encode(
                    AbiEncoder.b(sigEncoding), AbiEncoder.b(userListEncoding), AbiEncoder.s(msg), AbiEncoder.s(ev),
                    AbiEncoder.u(BigInteger.valueOf(T_D)), AbiEncoder.u(BigInteger.valueOf(idx)),
                    AbiEncoder.u(coordX(T_i)), AbiEncoder.u(coordY(T_i))
            );
        } catch (IOException ex) {
            throw new CryptoException("Failed to ABI-encode chain-challenge preimage", ex);
        }
        Element out = context.getCryptoParams().Zr.newElement();
        hashingService.hash(out, preimage);
        return out;
    }

    // -------------------------------------------------------------------
    // Coordinate/scalar extraction - mirrors secureChanelFree.java's
    // existing toDecimal(Element)/formatG1ForSolidity pattern (element.
    // toString() for scalars, Point<Element>.getX()/getY() for points),
    // just returning BigInteger instead of building a display string.
    // -------------------------------------------------------------------

    @SuppressWarnings("unchecked")
    private static BigInteger coordX(Element point) {
        return new BigInteger(((Point<Element>) point).getX().toString());
    }

    @SuppressWarnings("unchecked")
    private static BigInteger coordY(Element point) {
        return new BigInteger(((Point<Element>) point).getY().toString());
    }

    private static BigInteger toBigInt(Element scalar) {
        return new BigInteger(scalar.toString());
    }
}
