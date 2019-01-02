package MessageType;

import java.io.Serializable;

public class AesKeyWithDigitalSignature implements Serializable {
    
    //private static final long serialVersionUID = 6529685098267757690L;
    private byte[] cipherKeyAES;
    private byte[] signature;

    public AesKeyWithDigitalSignature(byte[] cipherKeyAES, byte[] signature) {
        this.cipherKeyAES = cipherKeyAES;
        this.signature = signature;
    }

    public byte[] getCipherKeyAES() {
        return cipherKeyAES;
    }

    public byte[] getSignature() {
        return signature;
    }
}