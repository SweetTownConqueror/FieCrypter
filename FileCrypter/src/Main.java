import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;



public class Main {

	public static void main(String[] args) throws InvalidKeyException, NoSuchPaddingException, FileNotFoundException, IllegalBlockSizeException, BadPaddingException, IOException, InvalidKeySpecException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		//on lance le script de la facon suivante:
		//.jar [path to directory to be encrypted] [action]
		//[action]: rsa, crypter, decrypter
		
		//TODO: voir si on peut pas plutot mettre une clé AES 256 bits
		if(args.length == 2) {
			@SuppressWarnings("unused")
			Crypter t = new Crypter(args);
		}else {
			System.out.println("ERROR : script must take 2 arguments : ");
			System.out.println("[path to directory to be encrypted] [action]");
			System.out.println("[action]: rsa, crypter, decrypter");
		}
		
	}

}
