package bclrspaper;

import java.util.ArrayList;
import bclrspaper.model.designatedUserParamSCF;
import bclrspaper.model.mainSecretKey;
import bclrspaper.model.periodKeyPackage;
import bclrspaper.model.signatureVals;
import bclrspaper.model.userPublicValues;
import it.unisa.dia.gas.jpbc.Element;

public class testRingSignature {
    public static void main(String[] args) throws CryptoException {
        secureChanelFree scf = new secureChanelFree();
        scf.setup();

        String userID = "justo@github.com";
        int T_M = 30;
        ArrayList<userPublicValues> userPubVals = scf.setSecretValue(userID, T_M);

        ArrayList<designatedUserParamSCF> designatedUserPubParams = scf.partialPrivateKeyExtract(userID, userPubVals, T_M);

        // Extract: recovers the long-term main secret key sk_{ID_i} = (u_i, D_i, rho_i). No T_D
        // dependency any more - the per-period signing key is derived on
        // demand below, as many times as needed, without ever retaining
        // any of them.
        mainSecretKey msk = scf.setPrivateKey(designatedUserPubParams, userID, T_M);

        // ArrayList<userPubKey> pubKey = scf.setPubKey(userID, designatedUserPubParams, T_M);

        // Build the ring: 4 members, signer at index 1
        String[] L = {"hi@qq.com", userID, "security@outlook.com", "ytx@qq.com"};
        int piIndex = 1;

        // Real U_ID_i for the signer (from setSecretValue); independent, plausible,
        // already-"registered" U_ID_i for the other (decoy) ring members - in a real
        // deployment these are just other users' genuinely published values.
        java.security.SecureRandom rnd = new java.security.SecureRandom();
        Element[] ringUID = new Element[L.length];
        for (int i = 0; i < L.length; i++) {
            if (i == piIndex) {
                ringUID[i] = userPubVals.get(0).getUID_i().duplicate();
            } else {
                Element decoyU = scf.getZr().newRandomElement();
                ringUID[i] = scf.getG1Gen().duplicate().mulZn(decoyU);
            }
        }

        String ev = "BCSCFFSKI-SBv-2026";
        String msg = "RS with BN254";
        String fakeMsg = "RS with no BN254";
        int T_D = 15;

        // --- DeriveEphemeralKey: on-demand, stateless period-key derivation ---
        System.out.println("\n--- Deriving period key for T_D=" + T_D + " ---");
        periodKeyPackage ek15 = scf.deriveEphemeralKey(msk, userID, T_M, T_D);

        ArrayList<signatureVals> sigVals = scf.ringSign(ev, L, piIndex, ek15, msk.getU_i(), msg, T_D, ringUID);

        boolean okReal = scf.ringVerify(sigVals, L, msg, ev, T_D, ringUID);
        System.out.println("Verification on real message: " + okReal);

        boolean okTampered = scf.ringVerify(sigVals, L, fakeMsg, ev, T_D, ringUID);
        System.out.println("Verification on tampered message: " + okTampered);

        // --- Forward security / key insulation demo: KeyRenewal and
        // KeyAccess are both just DeriveEphemeralKey at a different T_D,
        // called directly from msk - no state carried over from ek15 above,
        // demonstrating the "never chained from each other" guarantee. ---
        System.out.println("\n--- KeyRenewal (future period) and KeyAccess (past period) ---");
        int T_Dnext = T_D + 1;
        int T_Dprev = T_D - 1;
        periodKeyPackage ekNext = scf.keyRenewal(msk, userID, T_M, T_Dnext);
        periodKeyPackage ekPrev = scf.keyAccess(msk, userID, T_M, T_Dprev);

        ArrayList<signatureVals> sigNext = scf.ringSign(ev, L, piIndex, ekNext, msk.getU_i(), msg, T_Dnext, ringUID);
        boolean okNext = scf.ringVerify(sigNext, L, msg, ev, T_Dnext, ringUID);
        System.out.println("Verification at renewed period T_D=" + T_Dnext + ": " + okNext);

        ArrayList<signatureVals> sigPrev = scf.ringSign(ev, L, piIndex, ekPrev, msk.getU_i(), msg, T_Dprev, ringUID);
        boolean okPrev = scf.ringVerify(sigPrev, L, msg, ev, T_Dprev, ringUID);
        System.out.println("Verification at accessed period T_D=" + T_Dprev + ": " + okPrev);

        // --- Linkability demo: two signatures by the same signer under the
        // same (ev,T_D) must Link, regardless of message; a signature under
        // a different event must not. ---
        System.out.println("\n--- Linkability ---");
        ArrayList<signatureVals> sigVals2 = scf.ringSign(ev, L, piIndex, ek15, msk.getU_i(), fakeMsg, T_D, ringUID);
        boolean linkedSameEvent = scf.link(sigVals.get(0), sigVals2.get(0));
        System.out.println("Same signer, same (ev,T_D), different message -> Linked: " + linkedSameEvent + " (expected true)");

        String ev2 = "BCSCFFSKI-SBv-2027";
        periodKeyPackage ek15Ev2 = scf.deriveEphemeralKey(msk, userID, T_M, T_D);
        ArrayList<signatureVals> sigValsOtherEvent = scf.ringSign(ev2, L, piIndex, ek15Ev2, msk.getU_i(), msg, T_D, ringUID);
        boolean linkedDiffEvent = scf.link(sigVals.get(0), sigValsOtherEvent.get(0));
        System.out.println("Same signer, different ev -> Linked: " + linkedDiffEvent + " (expected false)");

        System.out.println("\n--- Ring U_ID_i values (for publishUserPublicParams / on-chain lookup) ---");
        for (int i = 0; i < L.length; i++) {
            System.out.println(L[i] + " -> " + formatPoint(ringUID[i]));
        }
    }

    @SuppressWarnings("unchecked")
    private static String formatPoint(Element e) {
        it.unisa.dia.gas.jpbc.Point<Element> p = (it.unisa.dia.gas.jpbc.Point<Element>) e;
        return "G1Point(" + p.getX() + ", " + p.getY() + ")";
    }
}
