package MessageType;

import java.io.Serializable;

public class DesKeyWithDigSig implements Serializable {
    
    //private static final long serialVersionUID = 6529685098267757690L;
    private byte[] cipherKeyDES;
    private byte[] dig_signature;

    public DesKeyWithDigSig(byte[] cipherKeyDES, byte[] signature) {
        this.cipherKeyDES = cipherKeyDES;
        this.dig_signature = signature;
    }

    public byte[] getCipherKeyDES() {
        return cipherKeyDES;
    }

    public byte[] getSignature() {
        return dig_signature;
    }
}
