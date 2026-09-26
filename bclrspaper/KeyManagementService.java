package bclrspaper;

import java.util.ArrayList;
import bclrspaper.model.designatedUserParamSCF;
import bclrspaper.model.mainSecretKey;
import bclrspaper.model.userPubKey;
import bclrspaper.model.userPublicValues;
import it.unisa.dia.gas.jpbc.Element;

public class KeyManagementService {
    private final CryptoContext context;
    private final HashingService hashingService;
    private Element userSecretValue;
    // rho_i: hash-chain seed for forward-security / key-insulation
    // Sampled once at registration alongside u_i, and - unlike U_ID_i/Q_ID_i/V_ID_i/W_ID_i -
    // never published: it becomes part of the user's main secret key
    // sk_{ID_i} = (u_i, D_i, rho_i), returned only from setPrivateKey below.
    private Element chainSeed;

    public KeyManagementService(CryptoContext context, HashingService hashingService) {
        this.context = context;
        this.hashingService = hashingService;
    }

    public ArrayList<userPublicValues> setSecretValue(String userID, int T_M) throws CryptoException {
        userSecretValue = context.getCryptoParams().Zr.newRandomElement().getImmutable();
        chainSeed = context.getCryptoParams().Zr.newRandomElement().getImmutable();
        Element v = context.getCryptoParams().Zr.newRandomElement();

        userPublicValues userPublicElements = new userPublicValues();
        userPublicElements.setUID_i(context.getCryptoParams().G.duplicate().mulZn(userSecretValue));
        userPublicElements.setQID_i(context.getCryptoParams().G1.newRandomElement());
        String prepHash_1 = userID + T_M;
        hashingService.hash(userPublicElements.getQID_i(), prepHash_1);
        userPublicElements.setVID_i(userPublicElements.getQID_i().duplicate().getImmutable().mulZn(userSecretValue.mulZn(v)));
        // W_ID_i lives in G2 to allow for asymmetric pairing: e(V_ID_i, G2gen) == e(Q_ID_i, W_ID_i).
        userPublicElements.setWID_i(context.getCryptoParams().G2gen.duplicate().mulZn(userSecretValue.mulZn(v)));

        ArrayList<userPublicValues> userPublicVals = new ArrayList<>();
        userPublicVals.add(userPublicElements);
        return userPublicVals;
    }

    public ArrayList<designatedUserParamSCF> partialPrivateKeyExtract(String userID, ArrayList<userPublicValues> userPubVals, int T_M) throws CryptoException {
        // Consistency check: e(V_ID_i, G2gen) == e(Q_ID_i, W_ID_i).
        Element outLeft = context.getCryptoParams().pairing.pairing(userPubVals.get(0).getVID_i().duplicate(), context.getCryptoParams().G2gen.duplicate());
        Element outRight = context.getCryptoParams().pairing.pairing(userPubVals.get(0).getQID_i().duplicate(), userPubVals.get(0).getWID_i().duplicate());
        if (outLeft.isEqual(outRight)) {
            designatedUserParamSCF userSpecificParams = new designatedUserParamSCF();
            // D_i = masterSecret * Q_ID_i and R_ID_i = masterSecret * U_ID_i
            // are direct scalar multiplications by the KGC's raw private scalar.
            Element D_i = userPubVals.get(0).getQID_i().duplicate().getImmutable().mulZn(context.getMasterPrivateKey());
            Element R_ID_i = userPubVals.get(0).getUID_i().duplicate().mulZn(context.getMasterPrivateKey());
            userSpecificParams.setS(context.getCryptoParams().Zr.newElement());
            String prepHash_3 = userID + T_M + R_ID_i;
            hashingService.hash(userSpecificParams.getS(), prepHash_3);
            userSpecificParams.setYID_i(context.getCryptoParams().G1.newElement());
            userSpecificParams.setYID_i(R_ID_i.sub(D_i).add(userPubVals.get(0).getUID_i().duplicate().mulZn(context.getMasterPrivateKey().mulZn(userSpecificParams.getS()))));
            userSpecificParams.setUID_i(userPubVals.get(0).getUID_i().duplicate());

            ArrayList<designatedUserParamSCF> designatedUserPubParams = new ArrayList<>();
            designatedUserPubParams.add(userSpecificParams);
            return designatedUserPubParams;
        }

        ArrayList<designatedUserParamSCF> designatedUserPubParams = new ArrayList<>();
        designatedUserPubParams.add(new designatedUserParamSCF());
        return designatedUserPubParams;
    }

    /**
     * Extract: recovers the user's long-term main secret key
     * sk_{ID_i} = (u_i, D_i, rho_i) from the KGC's blinded-extraction
     * response, after the same consistency + pairing sanity checks. 
     */
    public mainSecretKey setPrivateKey(ArrayList<designatedUserParamSCF> desigUserParam, String userID, int T_M) throws CryptoException {
        // R_ID_i and the blinding recomputation below use MasterPublicKey
        // in G1 (same group as U_ID_i) - this is the KGC's public key
        // published in G1.
        Element R_ID_i = context.getMasterPublicKeyG1().mulZn(userSecretValue);
        Element sComputed = context.getCryptoParams().Zr.newElement();
        String prepHash_3 = userID + T_M + R_ID_i;
        hashingService.hash(sComputed, prepHash_3);
        if (!sComputed.isEqual(desigUserParam.get(0).getS())) {
            throw new CryptoException("KGC consistency check failed: recomputed s does not match the issued s.");
        }

        Element D_i = R_ID_i.add(context.getMasterPublicKeyG1().mulZn(userSecretValue.mulZn(desigUserParam.get(0).getS()))).sub(desigUserParam.get(0).getYID_i());
        Element Q_ID_i = context.getCryptoParams().G1.newRandomElement();
        String prepHash_1 = userID + T_M;
        hashingService.hash(Q_ID_i, prepHash_1);
        // Correctly-typed (G1 x G2) sanity check that the recovered D_i
        // really is masterSecret*Q_ID_i - uses the G2 generator and the
        // G2 copy of MasterPublicKey (the contract's kgcPubKeyG2), since
        // D_i and Q_ID_i are both G1.
        Element outLeft = context.getCryptoParams().pairing.pairing(D_i, context.getCryptoParams().G2gen.duplicate());
        Element outRight = context.getCryptoParams().pairing.pairing(Q_ID_i, context.getMasterPublicKeyG2().duplicate());
        if (!outLeft.isEqual(outRight)) {
            throw new CryptoException("Pairing sanity check failed: recovered D_i is not s*Q_ID_i.");
        }

        return new mainSecretKey(userSecretValue, D_i.getImmutable(), chainSeed);
    }

    public ArrayList<userPubKey> setPubKey(String userID, ArrayList<designatedUserParamSCF> desigUserParam, int T_M) throws CryptoException {
        userPubKey pubKey = new userPubKey();
        pubKey.setQID_i(context.getCryptoParams().G1.newRandomElement());
        String prepHash_1 = userID + T_M;
        hashingService.hash(pubKey.getQID_i(), prepHash_1);
        pubKey.setY_i(desigUserParam.get(0).getUID_i());
        ArrayList<userPubKey> userPublicKey = new ArrayList<>();
        userPublicKey.add(pubKey);
        return userPublicKey;
    }
}
