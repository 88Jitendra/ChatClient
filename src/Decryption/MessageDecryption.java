package Decryption;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

public class MessageDecryption {
    
    private String message;
    private long time;
    private String type;
    
    public MessageDecryption(String message, Key key,String type) {
        
        try {
            byte[] cipherText = new byte[message.length()];
            char[] carr = message.toCharArray();
            for (int i = 0; i < message.length(); i++) {
                cipherText[i] = (byte) carr[i];
            }

            // Creates the Cipher object (specifying the algorithm, mode, and padding)
            Cipher cipher = Cipher.getInstance(type + "/ECB/PKCS5Padding");

            // decrypt the ciphertext using the same key
            System.out.println("\nStart decryption");
            final long startTime = System.nanoTime();
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] newPlainText = cipher.doFinal(cipherText);
            final long duration = System.nanoTime() - startTime;
            System.out.println("Finish decryption: ");

            //System.out.println(new String(newPlainText, StandardCharsets.UTF_8));
            this.message = new String(newPlainText, StandardCharsets.UTF_8);
            time = duration;
            System.out.println("Message length is " + this.message.length());

        } catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException e) {
            System.out.println("error");
            e.printStackTrace();
            
        }
    }

    public long getTime()
    {
        return time;
    }
    
    public String getMessage() {
        return message;
    }
}

