package bclrspaper.model;

import it.unisa.dia.gas.jpbc.Element;

/**
 * ek_i^{(D)} = (Atilde_i^{(D)}, sk_i^{T_D}), the period-key package produced
 * by PeriodKeyService.deriveEphemeralKey. Handed to RingSignatureService.ringSign as an opaque
 * object in place of a freshly-recomputed A_s basis.
 *
 * Note this does NOT replace u_i in ringSign: the ring-membership chain
 * (z_pi = k + e_pi*u_pi) and the key image (I = u_pi*H_ev) both still need
 * the raw witness u_pi directly - neither is a function of ek alone, since
 * ek's two components are u_pi blinded by (u_pi+t_p^{(D)})^{-1}, which is
 * not invertible back to u_pi without solving a DLOG-hard problem.
 */
public class periodKeyPackage {
    private final Element atilde;  // Q_i * (u_i + t_p^{(D)})^{-1}
    private final Element skTD;    // D_i * (u_i + t_p^{(D)})^{-1}

    public periodKeyPackage(Element atilde, Element skTD) {
        this.atilde = atilde;
        this.skTD = skTD;
    }

    public Element getAtilde() { return atilde; }
    public Element getSkTD() { return skTD; }
}
