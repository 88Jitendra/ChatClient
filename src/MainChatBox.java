
import Decryption.DecryptAesKeyWithRSAandDigSig;
import Decryption.DecryptDesKeyWithRSAandDS;
import Decryption.MessageDecryption;
import Encryption.MessageEncryption;
import MessageType.AesKeyWithDigitalSignature;
import MessageType.DesKeyWithDigSig;
import java.awt.RenderingHints.Key;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.logging.Level;
import java.util.logging.Logger;
//import javafx.application.Application;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class MainChatBox extends javax.swing.JFrame {

    private static SecretKey DESKey;
    private static byte[] byy = null;
    private static InputStream in;
    private Object msg_txt;
    private long time;
    String filename = "D:\\piyush.txt";
    public MainChatBox() {
        initComponents();
    }
    
    static Socket socket;
    static DataInputStream din;
    static DataOutputStream dout;
    static ObjectOutputStream output;
    static ObjectInputStream input;
    private static SecretKey AESKey;
    static String msg_from_bob;
    String msg_for_bob;
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jScrollPane1 = new javax.swing.JScrollPane();
        msg_area = new javax.swing.JTextArea();
        msgText = new javax.swing.JTextField();
        sendButton = new javax.swing.JButton();
        jLabel1 = new javax.swing.JLabel();
        decryptAes = new javax.swing.JButton();
        decryptDes = new javax.swing.JButton();
        encryptAes = new javax.swing.JButton();
        ecncryptDes = new javax.swing.JButton();
        decryptAes1 = new javax.swing.JButton();
        decryptDes2 = new javax.swing.JButton();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setTitle("ALICE");

        msg_area.setColumns(20);
        msg_area.setRows(5);
        jScrollPane1.setViewportView(msg_area);

        msgText.setFont(new java.awt.Font("Tahoma", 1, 12)); // NOI18N

        sendButton.setFont(new java.awt.Font("Tahoma", 1, 12)); // NOI18N
        sendButton.setText("SEND MESSAGE");
        sendButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                sendButtonActionPerformed(evt);
            }
        });

        jLabel1.setFont(new java.awt.Font("Tahoma", 1, 24)); // NOI18N
        jLabel1.setText("ALICE");

        decryptAes.setFont(new java.awt.Font("Tahoma", 1, 12)); // NOI18N
        decryptAes.setText("DECRYPT(AES)");
        decryptAes.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                decryptAesActionPerformed(evt);
            }
        });

        decryptDes.setFont(new java.awt.Font("Tahoma", 1, 12)); // NOI18N
        decryptDes.setText("DECRYPT(DES)");
        decryptDes.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                decryptDesActionPerformed(evt);
            }
        });

        encryptAes.setFont(new java.awt.Font("Tahoma", 1, 12)); // NOI18N
        encryptAes.setText("ENCRYPT(AES)");
        encryptAes.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                encryptAesActionPerformed(evt);
            }
        });

        ecncryptDes.setFont(new java.awt.Font("Tahoma", 1, 12)); // NOI18N
        ecncryptDes.setText("ENCRYPT(DES)");
        ecncryptDes.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                ecncryptDesActionPerformed(evt);
            }
        });

        decryptAes1.setFont(new java.awt.Font("Tahoma", 1, 12)); // NOI18N
        decryptAes1.setText("DECRYPT(AES)FILE");
        decryptAes1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                decryptAes1ActionPerformed(evt);
            }
        });

        decryptDes2.setFont(new java.awt.Font("Tahoma", 1, 12)); // NOI18N
        decryptDes2.setText("DECRYPT(DES)FILE");
        decryptDes2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                decryptDes2ActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jScrollPane1)
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(msgText, javax.swing.GroupLayout.PREFERRED_SIZE, 211, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(18, 18, 18)
                        .addComponent(sendButton, javax.swing.GroupLayout.PREFERRED_SIZE, 154, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(layout.createSequentialGroup()
                        .addGap(282, 282, 282)
                        .addComponent(jLabel1)))
                .addContainerGap(283, Short.MAX_VALUE))
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                    .addGroup(javax.swing.GroupLayout.Alignment.LEADING, layout.createSequentialGroup()
                        .addComponent(encryptAes, javax.swing.GroupLayout.PREFERRED_SIZE, 182, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(ecncryptDes, javax.swing.GroupLayout.PREFERRED_SIZE, 182, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(javax.swing.GroupLayout.Alignment.LEADING, layout.createSequentialGroup()
                        .addComponent(decryptAes, javax.swing.GroupLayout.PREFERRED_SIZE, 182, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(36, 36, 36)
                        .addComponent(decryptDes, javax.swing.GroupLayout.PREFERRED_SIZE, 182, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(decryptAes1, javax.swing.GroupLayout.PREFERRED_SIZE, 182, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(decryptDes2, javax.swing.GroupLayout.PREFERRED_SIZE, 182, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(41, 41, 41))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel1, javax.swing.GroupLayout.DEFAULT_SIZE, 38, Short.MAX_VALUE)
                .addGap(18, 18, 18)
                .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 209, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(36, 36, 36)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(msgText, javax.swing.GroupLayout.PREFERRED_SIZE, 34, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(sendButton, javax.swing.GroupLayout.PREFERRED_SIZE, 34, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(decryptAes, javax.swing.GroupLayout.PREFERRED_SIZE, 34, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(decryptDes, javax.swing.GroupLayout.PREFERRED_SIZE, 34, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(decryptAes1, javax.swing.GroupLayout.PREFERRED_SIZE, 34, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(encryptAes, javax.swing.GroupLayout.PREFERRED_SIZE, 34, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(ecncryptDes, javax.swing.GroupLayout.PREFERRED_SIZE, 34, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(decryptDes2, javax.swing.GroupLayout.PREFERRED_SIZE, 34, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(28, 28, 28))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void sendButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_sendButtonActionPerformed
        try {
            dout.writeUTF(msg_for_bob);
        } catch (IOException ex) {
            Logger.getLogger(MainChatBox.class.getName()).log(Level.SEVERE, null, ex);
        }
        msgText.setText("");
    }//GEN-LAST:event_sendButtonActionPerformed

    private void decryptAesActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_decryptAesActionPerformed
        // TODO add your handling code here:
        MessageDecryption mssg = new MessageDecryption(msg_from_bob,AESKey,"AES");
        msg_from_bob = mssg.getMessage();
        long tim = mssg.getTime();
        msg_area.setText(msg_area.getText() + "\n\nDecrypted Message(AES) : " + msg_from_bob + "\nTime : " + tim + "\n");
    }//GEN-LAST:event_decryptAesActionPerformed

    private void decryptDesActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_decryptDesActionPerformed

        MessageDecryption mssg = new MessageDecryption(msg_from_bob,DESKey,"DES");
        msg_from_bob = mssg.getMessage();
        long tim = mssg.getTime();
        msg_area.setText(msg_area.getText() + "\n\nDecrypted Message(DES) : " + msg_from_bob + "\nTime : " + tim + "\n");
    }//GEN-LAST:event_decryptDesActionPerformed

    private void encryptAesActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_encryptAesActionPerformed
        // TODO add your handling code here:
        msg_for_bob = msgText.getText().trim();
        msg_area.setText(msg_area.getText() + "\n \t \t You : " + msg_for_bob + "\n");
        try {
            MessageEncryption mssg = new MessageEncryption(msg_for_bob,AESKey,"AES");
            msg_for_bob = mssg.getMessage();
            time = mssg.getTime();
            msg_area.setText(msg_area.getText() + "\n \t \t EncryptedWithAES : " + msg_for_bob + "\n\nTime : " + time);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(MainChatBox.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(MainChatBox.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(MainChatBox.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(MainChatBox.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(MainChatBox.class.getName()).log(Level.SEVERE, null, ex);
        }
    }//GEN-LAST:event_encryptAesActionPerformed

    private void ecncryptDesActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_ecncryptDesActionPerformed
        // TODO add your handling code here:
        msg_for_bob = msgText.getText().trim();
        msg_area.setText(msg_area.getText() + "\n \t \t You : " + msg_for_bob + "\n");
        try {
            MessageEncryption mssg = new MessageEncryption(msg_for_bob,DESKey,"DES");
            msg_for_bob = mssg.getMessage();
            time = mssg.getTime();
            msg_area.setText(msg_area.getText() + "\n \t \t EncryptedWithDES : " + msg_for_bob + "\n\nTime : " + time);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(MainChatBox.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(MainChatBox.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(MainChatBox.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(MainChatBox.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(MainChatBox.class.getName()).log(Level.SEVERE, null, ex);
        }
    }//GEN-LAST:event_ecncryptDesActionPerformed
    
    
    private void decryptAes1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_decryptAes1ActionPerformed
        String message = msg_from_bob.substring((msg_from_bob.indexOf('/') + 1));
        System.out.println("mssg " + message);
        
        MessageDecryption mesg_dec = new MessageDecryption(message,AESKey,"AES");
        msg_from_bob = mesg_dec.getMessage();
        
        System.out.println("message(FILE) flag " + msg_from_bob + "\n");
        
        long tim = mesg_dec.getTime();
        try {
            DataOutputStream doo = new DataOutputStream(new FileOutputStream(filename));
            PrintWriter pw = new PrintWriter(new FileWriter(filename));
            char c;
            String nwln = System.getProperty("line.separator");
            //doo.writeChars(msg_from_bob);
            for(int i=0;i<msg_from_bob.length();i++){
                c = msg_from_bob.charAt(i);
                String s = "" + c;
                if(s.equals("/")){
                    doo.writeBytes(nwln);
                }else{
                    doo.write(c);
                }
            }
        } catch (IOException ex) {
            Logger.getLogger(MainChatBox.class.getName()).log(Level.SEVERE, null, ex);
        }
        msg_area.setText(msg_area.getText() + "\nTime : " + tim + "\n");
        
    }//GEN-LAST:event_decryptAes1ActionPerformed

    private void decryptDes2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_decryptDes2ActionPerformed
        String message = msg_from_bob.substring(msg_from_bob.indexOf('/') + 1);
        System.out.println("mssg " + message);
        
        MessageDecryption mesg_dec = new MessageDecryption(message,DESKey,"DES");
        msg_from_bob = mesg_dec.getMessage();
        System.out.println("message(FILE) " + msg_from_bob + "\n");
        long tim = mesg_dec.getTime();
        try {
            DataOutputStream doo = new DataOutputStream(new FileOutputStream(filename));
            char c;
            for(int i=0;i<msg_from_bob.length();i++){
                c = msg_from_bob.charAt(i);
                if(c == '/'){
                    doo.write('\n');
                }
                doo.write(c);
            }
        } catch (IOException ex) {
            Logger.getLogger(MainChatBox.class.getName()).log(Level.SEVERE, null, ex);
        }
        msg_area.setText(msg_area.getText() + "\nTime : " + tim + "\n");
        
    }//GEN-LAST:event_decryptDes2ActionPerformed

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) throws NoSuchAlgorithmException {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(MainChatBox.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(MainChatBox.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(MainChatBox.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(MainChatBox.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new MainChatBox().setVisible(true);
            }
        });
        
        try {
            socket = new Socket("localhost",6666);
            din = new DataInputStream(socket.getInputStream());
            dout = new DataOutputStream(socket.getOutputStream());
            
            //get PublicKeyOfBob
            PublicKey publicKeyOfBob = null;
            input = new ObjectInputStream(socket.getInputStream());
            try {
                publicKeyOfBob = (PublicKey)input.readObject();
            } catch (ClassNotFoundException ex) {
                Logger.getLogger(MainChatBox.class.getName()).log(Level.SEVERE, null, ex);
            }
            
            msg_area.setText(msg_area.getText().trim() + "\n\nI know Public Key Of Bob : " + publicKeyOfBob.toString() + "\n\n");
            
            //Generate Public And Private Key(RSA)
            KeyPairGenerator keyGenRSA = KeyPairGenerator.getInstance("RSA");
            keyGenRSA.initialize(1024);
            KeyPair keyRSA = keyGenRSA.generateKeyPair();
            PrivateKey keyRSAPrivate = keyRSA.getPrivate();
            PublicKey keyRSAPublic = keyRSA.getPublic();
            
            msg_area.setText(msg_area.getText().trim() + "\n\nI know My Public Key : " + keyRSAPublic.toString() + "\n\nI know My Private Key : " + keyRSAPrivate.toString() + "\n");
            
            //Send PublicKey To Bob
            output = new ObjectOutputStream(socket.getOutputStream());
            output.writeObject(keyRSAPublic);
            
            
            //Receiving Encrypted AES KeyObject From Alice
            in = socket.getInputStream();

            byte[] b = new byte[128];
            in.read(b);
            byte[] b2 = new byte[128];
            in.read(b2);
            
            AesKeyWithDigitalSignature aesKeyDigitalAndSig = new AesKeyWithDigitalSignature(b,b2);
            System.out.println("error not here" + aesKeyDigitalAndSig.getCipherKeyAES() + "\n" + aesKeyDigitalAndSig.getSignature());
            DecryptAesKeyWithRSAandDigSig decryptKeyWithRSAandDS = new DecryptAesKeyWithRSAandDigSig(aesKeyDigitalAndSig.getCipherKeyAES(),keyRSAPrivate,publicKeyOfBob,aesKeyDigitalAndSig.getSignature());
            AESKey = decryptKeyWithRSAandDS.getKey();
            
            msg_area.setText(msg_area.getText().trim() + "\n\nDecryption (AES)Time : " + decryptKeyWithRSAandDS.getTime() + "\n\nCommon AESKey : " + AESKey + "\n\n\n");
            
            
            //Receiving Encrypted DES KeyObject From Alice
            DesKeyWithDigSig desKeyDigitalAndSig = null;
            try {
                desKeyDigitalAndSig = (DesKeyWithDigSig)input.readObject();
            } catch (ClassNotFoundException ex) {
                Logger.getLogger(MainChatBox.class.getName()).log(Level.SEVERE, null, ex);
            }
            
            System.out.println("error not here" + desKeyDigitalAndSig.getCipherKeyDES() + "\n" + desKeyDigitalAndSig.getSignature());
            DecryptDesKeyWithRSAandDS decryptDesKeyWithRSAandDS = new DecryptDesKeyWithRSAandDS(desKeyDigitalAndSig.getCipherKeyDES(),keyRSAPrivate,publicKeyOfBob,desKeyDigitalAndSig.getSignature());
            DESKey = decryptDesKeyWithRSAandDS.getKey();
            msg_area.setText(msg_area.getText().trim() + "\n\nDecryption (DES)Time : " + decryptDesKeyWithRSAandDS.getTime() + "\n\nCommon DESKey : " + DESKey + "\n\n\n");
           
            
            msg_from_bob = "";
            while(!msg_from_bob.equals("exit"))
            {
                msg_from_bob = din.readUTF();
                if(msg_from_bob.contains("file")){
                    msg_area.setText(msg_area.getText().trim() + "\nBob's Send A file : \n" + msg_from_bob + "\n");
                }else
                    msg_area.setText(msg_area.getText().trim() + "\nBob's Cipher Text : " + msg_from_bob + "\n");
            }
          

        } catch (IOException ex) {
            System.out.println("err hre 1");
            Logger.getLogger(MainChatBox.class.getName()).log(Level.SEVERE, null, ex);
        }
        
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton decryptAes;
    private javax.swing.JButton decryptAes1;
    private javax.swing.JButton decryptDes;
    private javax.swing.JButton decryptDes2;
    private javax.swing.JButton ecncryptDes;
    private javax.swing.JButton encryptAes;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JTextField msgText;
    public static javax.swing.JTextArea msg_area;
    private javax.swing.JButton sendButton;
    // End of variables declaration//GEN-END:variables
}
