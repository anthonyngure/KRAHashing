/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

/**
 *
 * @author jimyk
 */
public class KRAHASHGenerator {

    /**
     * @param args the command line arguments
     */
    
    private static final String PRODUCTION_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq+Aqv672qZOMRCM9IjIs3n9iiAJ7buOSd/DjPqSgwu7qmYhCQGtXyf9PvJDvMxwHN6w9uPpLF4HZ566sGlPzYXsbFXIeeF4GWfvAjBAnDsz60SM+t0/UNzgtq6Qg0mWFCKcQKMfvHH8ViZtXg1agWjK5adc0a61cnD8qA0i0Oh6MD0NKbx4zW8jeWvQX/0HuNdl6WEhjqa0kXx9s4SQ8ySS76hVU7NSYNNLmZbuSOYN8/insJ0LMarrevGZ10JtlditRiqoAhOZQIvhPIiO4esSwT+esfXj6IGHDiRqApa77OvXgnuiU9lD/5/C/Ii2Gl/UEkcNKJ1so4TzvW4cgGQIDAQAB";
    private static final String INVOICE_URL = "https://tims-test.kra.go.ke/TIMS/tims/receiveInvoicetDtls?MSN=KRAMW422202004004479&MTYP=B";
    private static final String EOD_URL = "https://tims-test.kra.go.ke/TIMS/tims/receiveEODSummaryDtls?MSN=KRAMW422202004004479&MTYP=B";
    public static byte[] getSHA(String input) throws NoSuchAlgorithmException 
    {  
        // Static getInstance method is called with hashing SHA  
        MessageDigest md = MessageDigest.getInstance("SHA-256");  
  
        // digest() method called  
        // to calculate message digest of an input  
        // and return array of byte 
        return md.digest(input.getBytes(StandardCharsets.UTF_8));  
    } 
    
    public static String toHexString(byte[] hash) 
    { 
        // Convert byte array into signum representation  
        BigInteger number = new BigInteger(1, hash);  
  
        // Convert message digest into hex value  
        StringBuilder hexString = new StringBuilder(number.toString(16));  
  
        // Pad with leading zeros 
        while (hexString.length() < 32)  
        {  
            hexString.insert(0, '0');  
        }  
  
        return hexString.toString();  
    } 
    public static void main(String[] args) throws InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        try {
            // TODO code application logic here
            String hash_string = "";
            String algorithm = "RSA";  // or RSA, DH, etc.
            String DeviceType = "B";
            String SerialNumber = "KRAMW422202004004479";
            String NumberOFLastInvoiceSent = "4220044790000000003";
            String PinOfSeller = "P051448131C";

            
            DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
            Date date = new Date();
            String TransactionDate = dateFormat.format(date);
            
            String signature = DeviceType+""+TransactionDate+""+NumberOFLastInvoiceSent+""+PinOfSeller+""+SerialNumber;
            
            hash_string = toHexString(getSHA(signature));
            System.out.println(hash_string);
            
            byte[] Hash_Byte = hash_string.getBytes(StandardCharsets.UTF_8);
            byte[] Prod_key_Byte = Base64.decodeBase64(PRODUCTION_KEY);
            
            EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(Prod_key_Byte);
            
            KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
            
            PublicKey newPublicKey = keyFactory.generatePublic(pubKeySpec);
            
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");   
            cipher.init(Cipher.ENCRYPT_MODE, newPublicKey);
            byte[] secret = cipher.doFinal(Hash_Byte);
            
            String hash = Hex.encodeHexString(secret);
            
            System.out.println(hash);
            
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(KRAHASHGenerator.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
}
