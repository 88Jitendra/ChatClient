package Encryption;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

public class MessageEncryption {
    private String message;
    private long time;
    public MessageEncryption(String message, Key key,String type) throws NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException {
        byte[] plainText = message.getBytes(StandardCharsets.UTF_8);
        Cipher cipher = Cipher.getInstance(type + "/ECB/PKCS5Padding");
        // encrypt using the key and the plaintext
        System.out.println("\nStart encryption using :" + type);

        final long startTime = System.nanoTime();
        //  Initializes the Cipher object
        cipher.init(Cipher.ENCRYPT_MODE, key);

        // Calculates the ciphertext with a plaintext string.
        byte[] cipherText = cipher.doFinal(plainText);
        String str2="";

        for (byte b:cipherText) {
            str2 +=(char)b;
        }
        this.message = str2;
        final long duration = System.nanoTime() - startTime;
        time = duration;
        System.out.println("Finish encryption using : " + type);
        System.out.println("It took " + duration + " nanosecond to encrypt the message \"" + message +"\" using AES");
        System.out.println("Message length is " + message.length());
    }

    public String getMessage() {
        return message;
    }
    
    public long getTime()
    {
        return time;
    }
}
