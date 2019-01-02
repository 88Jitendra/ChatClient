package Decryption;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;


import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

public class DecryptDesKeyWithRSAandDS {
    private SecretKey key;
    private long time;
    
    public DecryptDesKeyWithRSAandDS(byte[] cipherText, PrivateKey privateKey, PublicKey publicKey, byte[] signature) {
        // verify the signature with the public key
        //System.out.println("\nStart signature verification");
        Signature sig2;
        try {
            sig2 = Signature.getInstance("MD5WithRSA");
            sig2.initVerify(publicKey);                        // Verifies the signature.
            sig2.update(cipherText);
            final long startTime = System.nanoTime();
            if (sig2.verify(signature)) {
                //System.out.println("Signature verified");

                // Now decrypt the message
                try {
                    // get an RSA cipher object
                    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

                    // decrypt the ciphertext using the private key
                    //System.out.println("\nStart decryption");
                    cipher.init(Cipher.DECRYPT_MODE, privateKey);
                    byte[] newPlainText = cipher.doFinal(cipherText);
                    //System.out.println("Finish decryption: ");

                    key = new SecretKeySpec(newPlainText, "DES");
                    final long duration = System.nanoTime() - startTime;
                    time = duration;
                } catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException e) {
                    e.printStackTrace();
                    System.out.println("errrr");
                }
            } else System.out.println("Signature failed");
        } catch (NullPointerException | NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
        }
    }
    
    public long getTime()
    {
        return time;
    }

    public SecretKey getKey() {
        return key;
    }
    
}
