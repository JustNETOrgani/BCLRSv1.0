package bclrspaper;

import java.util.ArrayList;
import bclrspaper.model.designatedUserParamSCF;
import bclrspaper.model.mainSecretKey;
import bclrspaper.model.periodKeyPackage;
import bclrspaper.model.signatureVals;
import bclrspaper.model.userPubKey;
import bclrspaper.model.userPublicValues;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Point;

public class secureChanelFree {
    private cryptoParams cryptoParam;
    private Element xInv;
    public Element X;    // G2 master public key - kgcPubKeyG2
    public Element X_G1; // G1 master public key - kgcPubKeyG1, used internally for blinding
    private CryptoContext cryptoContext;
    private final HashingService hashingService = new HashingService();
    private KeyManagementService keyManagementService;
    private RingSignatureService ringSignatureService;
    private PeriodKeyService periodKeyService;

    public void setup() {
        if (cryptoContext != null && cryptoParam != null && xInv != null) {
            System.out.println("Setup already executed!");
            return;
        }
        try {
            cryptoContext = new CryptoContext();
            cryptoContext.initialize();
            cryptoParam = cryptoContext.getCryptoParams();
            xInv = cryptoContext.getMasterPrivateKey();
            X = cryptoContext.getMasterPublicKeyG2();
            X_G1 = cryptoContext.getMasterPublicKeyG1();
            keyManagementService = new KeyManagementService(cryptoContext, hashingService);
            ringSignatureService = new RingSignatureService(cryptoContext, hashingService);
            periodKeyService = new PeriodKeyService(cryptoContext, hashingService);
            printStatements();
        } catch (CryptoException ex) {
            throw new IllegalStateException("Unable to initialize cryptographic context", ex);
        }
    }

    public ArrayList<userPublicValues> setSecretValue(String userID, int T_M) throws CryptoException {
        ensureInitialized();
        ArrayList<userPublicValues> userPublicVals = keyManagementService.setSecretValue(userID, T_M);
        printUserPublicVals(userPublicVals);
        return userPublicVals;
    }

    public ArrayList<designatedUserParamSCF> partialPrivateKeyExtract(String userID, ArrayList<userPublicValues> userPubVals, int T_M) throws CryptoException {
        ensureInitialized();
        ArrayList<designatedUserParamSCF> designatedUserPubParams = keyManagementService.partialPrivateKeyExtract(userID, userPubVals, T_M);
        printDesigUserParams(designatedUserPubParams);
        return designatedUserPubParams;
    }

    /** Extract, unmodified: recovers the user's long-term sk_{ID_i}=(u_i,D_i,rho_i). */
    public mainSecretKey setPrivateKey(ArrayList<designatedUserParamSCF> desigUserParam, String userID, int T_M) throws CryptoException {
        ensureInitialized();
        return keyManagementService.setPrivateKey(desigUserParam, userID, T_M);
    }

    /** DeriveEphemeralKey(sk_{ID_i}, T_D) - realizes both KeyRenewal and KeyAccess. */
    public periodKeyPackage deriveEphemeralKey(mainSecretKey msk, String userID, int T_M, int T_D) throws CryptoException {
        ensureInitialized();
        return periodKeyService.deriveEphemeralKey(msk, userID, T_M, T_D);
    }

    /** KeyRenewal(sk_{ID_i}, T_{D+1}): DeriveEphemeralKey at a later period. */
    public periodKeyPackage keyRenewal(mainSecretKey msk, String userID, int T_M, int T_Dnext) throws CryptoException {
        ensureInitialized();
        return periodKeyService.keyRenewal(msk, userID, T_M, T_Dnext);
    }

    /** KeyAccess(sk_{ID_i}, T_{D-1}): DeriveEphemeralKey at an earlier period. */
    public periodKeyPackage keyAccess(mainSecretKey msk, String userID, int T_M, int T_Dprev) throws CryptoException {
        ensureInitialized();
        return periodKeyService.keyAccess(msk, userID, T_M, T_Dprev);
    }

    public ArrayList<userPubKey> setPubKey(String userID, ArrayList<designatedUserParamSCF> desigUserParam, int T_M) throws CryptoException {
        ensureInitialized();
        return keyManagementService.setPubKey(userID, desigUserParam, T_M);
    }

    public ArrayList<signatureVals> ringSign(String ev, String[] L, int piIndex, periodKeyPackage ek, Element u_pi, String msg, int T_D,
                                              Element[] ringUID) throws CryptoException {
        ensureInitialized();
        System.out.println("Generating ring signature on: " + msg + " ...Please wait...");
        ArrayList<signatureVals> sigmaS = ringSignatureService.ringSign(ev, L, piIndex, ek, u_pi, msg, T_D, ringUID);
        System.out.println("Ring signature successfully generated.");
        printRingSig(sigmaS);
        return sigmaS;
    }

    public boolean ringVerify(ArrayList<signatureVals> sigmaS, String[] L, String msg, String ev, int T_D, Element[] ringUID) throws CryptoException {
        ensureInitialized();
        System.out.println("Verifying ring signature. Please wait...");
        return ringSignatureService.ringVerify(sigmaS, L, msg, ev, T_D, ringUID);
    }

    /** Link(sigma, sigma'): equal key images => same signer (except probability 1/r). */
    public boolean link(signatureVals a, signatureVals b) {
        return RingSignatureService.link(a, b);
    }

    public void printStatements() {
        System.out.println("============ Public Key Parameters ==============");
        System.out.println("Generator (g1): " + formatG1ForSolidity(cryptoParam.G));
        System.out.println("Generator (g2): " + formatG2ForSolidity(cryptoParam.G2gen));
        System.out.println("Generator (H_FIXED, G1, seed=\"" + CryptoContext.H_FIXED_SEED + "\"): " + formatG1ForSolidity(cryptoParam.H_FIXED));
        System.out.println("============== PKG Parameters ===============");
        System.out.println("PRIVATE KEY OF KGC xInv : " + xInv);
        System.out.println("PUBLIC KEY OF KGC X (G1): " + formatG1ForSolidity(X_G1));
        System.out.println("PUBLIC KEY OF KGC X (G2): " + formatG2ForSolidity(X));
        System.out.println("=================================================\n");
    }

    public void printDesigUserParams(ArrayList<designatedUserParamSCF> dUparams) {
        if (dUparams == null || dUparams.isEmpty()) return;
        System.out.println("============ Specific user Public Parameters ==============");
        System.out.println("Y_ID_i (blinded response, G1): " + formatG1ForSolidity(dUparams.get(0).getYID_i()));
        System.out.println("s: " + toDecimal(dUparams.get(0).getS()));
        System.out.println("=================================================\n");
    }

    public void printUserPublicVals(ArrayList<userPublicValues> userPubVals) {
        if (userPubVals == null || userPubVals.isEmpty()) return;
        System.out.println("============ Specific user Public Values ==============");
        System.out.println("Q_ID_i: " + formatG1ForSolidity(userPubVals.get(0).getQID_i()));
        System.out.println("U_ID_i: " + formatG1ForSolidity(userPubVals.get(0).getUID_i()));
        System.out.println("V_ID_i: " + formatG1ForSolidity(userPubVals.get(0).getVID_i()));
        System.out.println("W_ID_i (G2): " + formatG2ForSolidity(userPubVals.get(0).getWID_i()));
        System.out.println("=================================================\n");
    }

    public void printRingSig(ArrayList<signatureVals> sigmaVals) {
        if (sigmaVals == null || sigmaVals.isEmpty()) return;
        signatureVals sv = sigmaVals.get(0);
        System.out.println("============ Sigma_s Parameters ==============");
        System.out.println("A_s: " + formatG1ForSolidity(sv.getA_s()));
        System.out.println("B_s: " + formatG1ForSolidity(sv.getB_s()));
        System.out.println("I (key image): " + formatG1ForSolidity(sv.getKeyImage()));
        // System.out.println("h_As: " + toDecimal(sv.getH_As()));
        System.out.println("eStart: " + toDecimal(sv.getEStart()));
        Element[] z = sv.getZ();
        StringBuilder zStr = new StringBuilder("[");
        for (int i = 0; i < z.length; i++) {
            zStr.append(toDecimal(z[i]));
            if (i != z.length - 1) zStr.append(", ");
        }
        zStr.append("]");
        System.out.println("z: " + zStr);
        System.out.println("=================================================\n");
    }

    @SuppressWarnings("unchecked")
    private String formatG1ForSolidity(Element element) {
        if (element == null) return "null";
        Point<Element> p = (Point<Element>) element;
        return "G1Point(" + toDecimal(p.getX()) + ", " + toDecimal(p.getY()) + ")";
    }

    @SuppressWarnings("unchecked")
    private String formatG2ForSolidity(Element element) {
        if (element == null) return "null";
        Point<Element> p = (Point<Element>) element;
        Point<Element> x = (Point<Element>) p.getX();
        Point<Element> y = (Point<Element>) p.getY();
        return "G2Point(" + toDecimal(x.getY()) + ", " + toDecimal(x.getX()) + ", "
                + toDecimal(y.getY()) + ", " + toDecimal(y.getX()) + ")";
    }

    private String toDecimal(Element element) {
        return element.toString();
    }

    private void ensureInitialized() {
        if (cryptoContext == null || cryptoParam == null || xInv == null || X == null) {
            setup();
        }
    }

    public it.unisa.dia.gas.jpbc.Field<?> getZr() {
        ensureInitialized();
        return cryptoParam.Zr;
    }

    public Element getG1Gen() {
        ensureInitialized();
        return cryptoParam.G;
    }
}
