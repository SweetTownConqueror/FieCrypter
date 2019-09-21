package RSACrypto;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RSAKeyPairGenerator {

    private PrivateKey privateKey;
    private PublicKey publicKey;
    private KeyPair pair;

    public RSAKeyPairGenerator() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        this.pair = keyGen.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();
    }

    public void writeToFile(String path, byte[] key) throws IOException {
        File f = new File(path);
        f.getParentFile().mkdirs();
        FileOutputStream fos = new FileOutputStream(f);
        fos.write(key);
        fos.flush();
        fos.close();
    }
    
    public void getKeyFromFile(String _pubKeyFile) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
    	//String pubKeyFile = ...;
    	byte[] bytes = Files.readAllBytes(Paths.get(_pubKeyFile));
    	X509EncodedKeySpec ks = new X509EncodedKeySpec(bytes);
    	//KeySpec ks = new X509EncodedKeySpec(bytes);
    	KeyFactory kf = KeyFactory.getInstance("RSA");
    	PublicKey pub = kf.generatePublic(ks);
    	System.out.println("key : "+pub);
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }
    
    public KeyPair getKeyPair() {
        return pair;
    }
    
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        RSAKeyPairGenerator keyPairGenerator = new RSAKeyPairGenerator();
        keyPairGenerator.writeToFile("testFolder/keys.pub", keyPairGenerator.getPublicKey().getEncoded());
        keyPairGenerator.writeToFile("testFolder/keys.priv", keyPairGenerator.getPrivateKey().getEncoded());
        System.out.println(Base64.getEncoder().encodeToString(keyPairGenerator.getPublicKey().getEncoded()));
        System.out.println(Base64.getEncoder().encodeToString(keyPairGenerator.getPrivateKey().getEncoded()));
        System.out.println("key from file: ");
        keyPairGenerator.getKeyFromFile("testFolder/keys.pub");
    }
}