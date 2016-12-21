package vn.ctnet.helper;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.util.encoders.Hex;

import Decoder.BASE64Decoder;
import Decoder.BASE64Encoder;

public class Security {
	
	/***
	 * Ma hoa MD5
	 * @param input
	 * @return
	 */
	public static String MD5(String input) {
		 try {
	            MessageDigest md = MessageDigest.getInstance("MD5");
	            byte[] messageDigest = md.digest(input.getBytes());
	            BigInteger number = new BigInteger(1, messageDigest);
	            String hashtext = number.toString(16);
	            while (hashtext.length() < 32) {
	                hashtext = "0" + hashtext;
	            }
	            return hashtext;
	        } catch (Exception e) {
	            throw new RuntimeException(e);
	        }
	}
	
	
	/***
	 * Encrypt TripleDES
	 * @param key
	 * @param data
	 * @return
	 * @throws Exception
	 */
	public static String encryptTripleDES(String key,String data) throws Exception
    {
        Cipher cipher=Cipher.getInstance("TripleDES");
        MessageDigest md5=MessageDigest.getInstance("MD5");
        md5.update(key.getBytes(),0,key.length());
        String keymd5 = new
        BigInteger(1,md5.digest()).toString(16).substring(0,24); 
        SecretKeySpec keyspec = new SecretKeySpec(keymd5.getBytes(),"TripleDES");
        cipher.init(Cipher.ENCRYPT_MODE,keyspec);
        byte[] stringBytes=data.getBytes();
        byte[] raw=cipher.doFinal(stringBytes);
        BASE64Encoder encoder = new  BASE64Encoder(); 
        String base64 =encoder.encode(raw);
        return base64;
    }
	/***
	 * Descrypt TripleDES
	 * @param key
	 * @param data
	 * @return
	 * @throws Exception
	 */
    public static String decryptTripleDES(String key,String data) throws Exception
    {
        Cipher cipher=Cipher.getInstance("TripleDES");
        MessageDigest
        md5=MessageDigest.getInstance("MD5");
        md5.update(key.getBytes(),0,key.length());
        String keymd5 = new
        BigInteger(1,md5.digest()).toString(16).substring(0,24); 
        SecretKeySpec keyspec = new SecretKeySpec(keymd5.getBytes(),"TripleDES");
        cipher.init(Cipher.DECRYPT_MODE,keyspec);
        BASE64Decoder decoder = new BASE64Decoder();
        byte[] raw = decoder.decodeBuffer(data);
        byte[] stringBytes = cipher.doFinal(raw);
        String result = new String(stringBytes);
        return result;
    }
    
    /***
     * Create Sign RSA
     * @param data
     * @param filePath
     * @return
     */
    public static String createSignRSA(String data, String filePath) {
        try {
            final File privKeyFile = new File(filePath);
            final byte[] privKeyBytes = readFile(privKeyFile);
            final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            final PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privKeyBytes);
            final PrivateKey pk = (PrivateKey) keyFactory.generatePrivate(privSpec);

            final Signature sg = Signature.getInstance("SHA1withRSA");

            sg.initSign(pk);
            sg.update(data.getBytes());
            final byte[] bDS = sg.sign();
            return new String(org.apache.commons.codec.binary.Base64.encodeBase64(bDS));
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return "";
    }
    
    /***
     * Check Sign RSA
     * @param sign
     * @param data
     * @param publicKeyFile
     * @return
     */
    public static boolean checkSignRSA(String sign, String data,String publicKeyFile) {
        try {
            File pubKeyFile = new File(publicKeyFile);
            byte[] pubKeyBytes = readFile(pubKeyFile);
            X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(pubKeyBytes);

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey k = (RSAPublicKey) keyFactory.generatePublic(pubSpec);

            Signature signature = Signature.getInstance("SHA1withRSA");
            signature.initVerify(k);
            signature.update(data.getBytes());

            return signature.verify(org.apache.commons.codec.binary.Base64
                    .decodeBase64(sign.getBytes()));

        } catch (Exception ex) {
            ex.printStackTrace();
            System.out.println(ex.getMessage());
        }

        return false;
    }
   
    public static byte[] readFile(final File file)
            throws FileNotFoundException, IOException {
        DataInputStream dis = null;
        try {
            dis = new DataInputStream(new FileInputStream(file));
            final byte[] data = new byte[(int) file.length()];
            dis.readFully(data);
            return data;
        } finally {
            if (dis != null) {
                dis.close();
            }
        }
    }
    
}
