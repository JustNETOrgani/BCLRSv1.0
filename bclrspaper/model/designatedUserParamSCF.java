package bclrspaper.model;

import it.unisa.dia.gas.jpbc.Element;

public class designatedUserParamSCF {
    private Element U_ID_i;
    private Element Y_ID_i; // KGC's blinded response: (1+s)*R_ID_i - D_i
    private Element s;      // KGC's consistency nonce: Hash(ID || T_M || R_ID_i)

    public Element getUID_i() {
        return U_ID_i;
    }

    public void setUID_i(Element U_ID_i) {
        this.U_ID_i = U_ID_i;
    }

    public Element getYID_i() {
        return Y_ID_i;
    }

    public void setYID_i(Element Y_ID_i) {
        this.Y_ID_i = Y_ID_i;
    }

    public Element getS() {
        return s;
    }

    public void setS(Element s) {
        this.s = s;
    }
}
