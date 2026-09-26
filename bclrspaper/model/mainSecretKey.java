package bclrspaper.model;

import it.unisa.dia.gas.jpbc.Element;

/**
 * The user's long-term "main secret key" sk_{ID_i} = (u_i, D_i, rho_i).
 * This must be kept securely - it plays the role of the "insulated" base
 * secret important for key-insulation and forward security. 
 * Every period's signing capability (ek_i^{(D)}, via PeriodKeyService.deriveEphemeralKey) is
 * derived from it on demand and never stored.
 *
 * u_i        - the user's original secret scalar (from SetSecretValue).
 * D_i        - the KGC-extracted key s*Q_i, recovered via the existing
 *              blinded-extraction protocol (KeyManagementService.setPrivateKey);
 *              unaffected by anything in the forward-security revision.
 * chainSeed  - rho_i, the hash-chain seed sampled once at registration
 *              (extends SetSecretValue); never published, never leaves
 *              this object.
 */
public class mainSecretKey {
    private final Element u_i;
    private final Element D_i;
    private final Element chainSeed;

    public mainSecretKey(Element u_i, Element D_i, Element chainSeed) {
        this.u_i = u_i;
        this.D_i = D_i;
        this.chainSeed = chainSeed;
    }

    public Element getU_i() { return u_i; }
    public Element getD_i() { return D_i; }
    public Element getChainSeed() { return chainSeed; }
}
