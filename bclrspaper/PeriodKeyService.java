package bclrspaper;

import bclrspaper.model.mainSecretKey;
import bclrspaper.model.periodKeyPackage;
import it.unisa.dia.gas.jpbc.Element;

/**
 * Implements DeriveEphemeralKey, the single stateless algorithm that realizes both
 * KeyRenewal and KeyAccess: neither call touches any previously derived
 * ephemeral key or intermediate chain value, only sk_{ID_i} and the target
 * T_D, so no ephemeral key material needs to be retained after use.
 */
public class PeriodKeyService {
    private final CryptoContext context;
    private final HashingService hashingService;

    public PeriodKeyService(CryptoContext context, HashingService hashingService) {
        this.context = context;
        this.hashingService = hashingService;
    }

    /**
     * rho_i^{(D)} := H^{D+1}(rho_i). No intermediate values are stored or
     * reused across calls - each invocation walks the chain from the raw
     * seed, so this is a direct, stateless function of (rho_i, D), 
     * never a function of a previously derived ephemeral value.
     */
    private Element chainValue(Element rho_i, int T_D) throws CryptoException {
        Element current = rho_i;
        for (int i = 0; i <= T_D; i++) {
            Element next = context.getCryptoParams().Zr.newElement();
            hashingService.hash(next, current.toString());
            current = next;
        }
        return current;
    }

    /**
     * DeriveEphemeralKey(sk_{ID_i}, T_D):
     *   1. rho_i^{(D)} = H^{D+1}(rho_i)
     *   2. t_p^{(D)}   = H(rho_i^{(D)} || ID_i || T_D)   -- secret.
     *   3. ek_i^{(D)}  = (Q_i*(u_i+t_p^{(D)})^{-1}, D_i*(u_i+t_p^{(D)})^{-1})
     * Q_i is recomputed deterministically the same way it is everywhere
     * else in this codebase (H1(ID||T_M)) - never a secret.
     */
    public periodKeyPackage deriveEphemeralKey(mainSecretKey msk, String userID, int T_M, int T_D) throws CryptoException {
        Element rho_D = chainValue(msk.getChainSeed(), T_D);

        Element t_p_D = context.getCryptoParams().Zr.newElement();
        String prepTpHash = rho_D.toString() + userID + T_D;
        hashingService.hash(t_p_D, prepTpHash);

        Element Q_i = context.getCryptoParams().G1.newRandomElement();
        String prepHash_1 = userID + T_M;
        hashingService.hash(Q_i, prepHash_1);

        Element denomInv = msk.getU_i().duplicate().add(t_p_D).invert().getImmutable();
        Element atilde = Q_i.duplicate().mulZn(denomInv.duplicate());
        Element skTD = msk.getD_i().duplicate().mulZn(denomInv.duplicate());

        return new periodKeyPackage(atilde, skTD);
    }

    /** KeyRenewal(sk_{ID_i}, T_{D+1}): same algorithm, later period. */
    public periodKeyPackage keyRenewal(mainSecretKey msk, String userID, int T_M, int T_Dnext) throws CryptoException {
        return deriveEphemeralKey(msk, userID, T_M, T_Dnext);
    }

    /** KeyAccess(sk_{ID_i}, T_{D-1}): same algorithm, earlier period. */
    public periodKeyPackage keyAccess(mainSecretKey msk, String userID, int T_M, int T_Dprev) throws CryptoException {
        return deriveEphemeralKey(msk, userID, T_M, T_Dprev);
    }
}
