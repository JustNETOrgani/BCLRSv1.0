package bclrspaper.model;

import it.unisa.dia.gas.jpbc.Element;

public class signatureVals {
    private Element A_s;
    private Element B_s;
    private Element keyImage; // I = u_pi * H_ev - the bound key image (replaces the old, unbound tag_s)
    // private Element h_As;

    // Ring-membership OR-proof (AOS-style, over u_i via combined base
    // g1+c*H_ev and combined target U_ID_i+c*keyImage)
    private Element eStart;   // canonicalized chain-entry challenge, e_0
    private Element[] z;      // per-slot responses, indexed in ring order (z[i] for L[i])

    public Element getA_s() { return A_s; }
    public void setA_s(Element A_s) { this.A_s = A_s; }

    public Element getB_s() { return B_s; }
    public void setB_s(Element B_s) { this.B_s = B_s; }

    public Element getKeyImage() { return keyImage; }
    public void setKeyImage(Element keyImage) { this.keyImage = keyImage; }

    public Element getEStart() { return eStart; }
    public void setEStart(Element eStart) { this.eStart = eStart; }

    public Element[] getZ() { return z; }
    public void setZ(Element[] z) { this.z = z; }
}
