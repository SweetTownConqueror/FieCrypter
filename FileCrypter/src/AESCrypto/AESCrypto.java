package AESCrypto;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.IOException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.util.Random;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import javax.crypto.spec.IvParameterSpec;

public class AESCrypto {
	
	public AESCrypto() throws NoSuchAlgorithmException, NoSuchPaddingException {
		
	}
	public static byte[][] generateAESKey() throws NoSuchAlgorithmException {
		KeyGenerator kgen = KeyGenerator.getInstance("AES");
		//TODO voir si on peut pas remplacer par du 256 bits
		kgen.init(128);
		SecretKey skey = kgen.generateKey();
		byte[] byteAESSKey = skey.getEncoded();
		
		byte[] iv = new byte[128/8];
		Random srandom = new SecureRandom();
		srandom.nextBytes(iv);
		byte[][] keyIVArr = {byteAESSKey, iv};
		return keyIVArr;
	}

	public FileOutputStream saveAESKeyRSAEncrypted(String _inputFile, PublicKey _pub, byte[] _aesKeyAndIV) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		FileOutputStream out = new FileOutputStream(_inputFile);
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, _pub);
		byte[] b = cipher.doFinal(_aesKeyAndIV);
		out.write(b);
		return out;
	}
	public PublicKey getPublicKey(String _pubKeyFile) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		//ici nous recupererons la clé publique dans le fichier généré par RSAKeyPairGenerator
		byte[] bytes = Files.readAllBytes(Paths.get(_pubKeyFile));
		X509EncodedKeySpec ks = new X509EncodedKeySpec(bytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		PublicKey pub = kf.generatePublic(ks);
		return pub;
	}
	public PrivateKey getPrivateKey(String _privKeyFile) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		//ici nous recupererons la clé publique dans le fichier généré par RSAKeyPairGenerator
		byte[] bytes = Files.readAllBytes(Paths.get(_privKeyFile));
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(bytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPrivateKey privKey = (RSAPrivateKey) kf.generatePrivate(spec);
		return privKey;
	}
	
	public void AESEncryptFile(SecretKey _aesSKey, IvParameterSpec _ivspec, String _inputFile, String _out) throws FileNotFoundException, IOException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException {
		Cipher ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
		ci.init(Cipher.ENCRYPT_MODE, _aesSKey, _ivspec);
		    processFile(ci, _inputFile, _out);
	}
	public void AESDecryptFile(SecretKeySpec _skey, IvParameterSpec _ivspec, String _inputFile, String _out) throws FileNotFoundException, IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		Cipher ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
		ci.init(Cipher.DECRYPT_MODE, _skey, _ivspec);
		    processFile(ci, _inputFile, _out);
	}
	
	public SecretKeySpec getAESKeyFromAESRSAEncrypted(String _inputFile, PrivateKey _rsaPrivateKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException {
		FileInputStream in = new FileInputStream(_inputFile);
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.DECRYPT_MODE, _rsaPrivateKey);
		byte[] b = new byte[128];
		in.read(b, 0, 128);
		in.close();
		byte[] keyb = cipher.doFinal(b);
		byte[] keyc = new byte[16];
		for(int i=0;i<16;i++) {
			keyc[i]=keyb[i];
		}
		SecretKeySpec skey = new SecretKeySpec(keyc, "AES");
		return skey;
	}
	
	public IvParameterSpec getIVFromAESRSAEncrypted(String _inputFile, PrivateKey _rsaPrivateKey) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		FileInputStream in = new FileInputStream(_inputFile);
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.DECRYPT_MODE, _rsaPrivateKey);
		byte[] iv = new byte[128];
		in.read(iv, 0, 128);
		in.close();
		byte[] ivb = cipher.doFinal(iv);
		byte[] ivc = new byte[16];
		for(int i=0;i<16;i++) {
			ivc[i]=ivb[i+16];
		}
		IvParameterSpec ivspec = new IvParameterSpec(ivc);
		return ivspec;
	}
	
	static private void processFile(Cipher ci, String _in,String _out)
		    throws javax.crypto.IllegalBlockSizeException,
		           javax.crypto.BadPaddingException,
		           java.io.IOException
		{
		
			FileInputStream in = new FileInputStream(_in);
			byte[] ibuf = new byte[1024];
		    int len;
		    FileOutputStream fos = new FileOutputStream(_out);
		    while ((len = in.read(ibuf)) != -1) {
		    	byte[] obuf = ci.update(ibuf, 0, len);
		    	if ( obuf != null ) fos.write(obuf);
		        //ci.update(ibuf, 0, len);
		    }
		    byte[] obuf = ci.doFinal();
		    if ( obuf != null ) {
		        fos.write(obuf);
		        fos.close();
		    }
		    in.close();
		    File f = new File(_in);
		    f.delete();
		}
	//	static private void processFile(Cipher ci, String _in,String _out)
//		    throws javax.crypto.IllegalBlockSizeException,
//		           javax.crypto.BadPaddingException,
//		           java.io.IOException
//		{
//		
//			FileInputStream in = new FileInputStream(_in);
//			byte[] ibuf = new byte[1024];
//		    int len;
//		    FileOutputStream fos = new FileOutputStream(_out);
//		    while ((len = in.read(ibuf)) != -1) {
//		    	byte[] obuf = ci.update(ibuf, 0, len);
//		    	if ( obuf != null ) fos.write(obuf);
//		        //ci.update(ibuf, 0, len);
//		    }
//		    //in.close();
//		    byte[] obuf = ci.doFinal();
//		    if ( obuf != null ) {
//		        fos.write(obuf);
//		        fos.close();
//		    }
//		}
	
	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, IOException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, SignatureException {
		////////////////////////////////////////////////////////////////////////
		/////   CRYPTAGE												   /////
		////////////////////////////////////////////////////////////////////////		
		AESCrypto a = new AESCrypto();
		//a.AESEncryptFile(_ci, _aesSKey, _ivspec, _inputFile, _out);
		
		//on genere une cle aes et un vecteur d'initialisation aleatoires
		byte[][] aesKeyAndIV = AESCrypto.generateAESKey();
		//on recupere la cle RSA publique
		PublicKey rsaPublicKey = a.getPublicKey("testFolder/keys.pub");
		//on sauvegarde la clé aes dans un fichier keys.enc
		byte[] keyAndIVConcat = new byte[aesKeyAndIV[0].length + aesKeyAndIV[1].length];
		System.arraycopy(aesKeyAndIV[0], 0, keyAndIVConcat, 0, aesKeyAndIV[0].length);
		System.arraycopy(aesKeyAndIV[1], 0, keyAndIVConcat, aesKeyAndIV[1].length, aesKeyAndIV[1].length);
		//a.saveAESKeyRSAEncrypted("testFolder/keys.enc", rsaPublicKey, keyAndIVConcat);
		
		
		//on crypte un fichier avec cette clé AES
		SecretKeySpec aesSKey = new SecretKeySpec(aesKeyAndIV[0], "AES");
		IvParameterSpec ivSpec = new IvParameterSpec(aesKeyAndIV[1]);
		
		//a.AESEncryptFile(aesSKey, ivSpec, "testFolder/a.png", "testFolder/a2.png");
		
		////////////////////////////////////////////////////////////////////////
		/////   DECRYPTAGE												   /////
		////////////////////////////////////////////////////////////////////////

		//a partir du fichier keys.priv on va reconstituer le fichier original
		//on recupere la cle RSA privee
		AESCrypto b = new AESCrypto();
		PrivateKey rsaPrivateKey = b.getPrivateKey("testFolder/keys.priv");
		//on decrypte la cle aes rsa encrypted pour l'utiliser afin de 
		//dechiffrer le fichier
		SecretKeySpec aesKey=b.getAESKeyFromAESRSAEncrypted("testFolder/keys.enc", rsaPrivateKey);
		IvParameterSpec iv = b.getIVFromAESRSAEncrypted("testFolder/keys.enc", rsaPrivateKey);
		System.out.println("rsaPrivateKey:"+rsaPrivateKey.toString());
		System.out.println("aeskey:"+aesKey.toString());
		System.out.println("iv:"+iv.toString());
		//b.AESDecryptFile(aesKey, iv, "testFolder/a2.png", "testFolder/a3.png");
	
	}

}
