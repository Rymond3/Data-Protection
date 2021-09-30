import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.nio.charset.StandardCharsets;

public class Test_RSA {
	
	static byte[] plaintext = new byte[] { (byte)49, (byte)49, (byte)49, (byte)49, (byte)49, (byte)49, (byte)49, (byte)49, (byte)49, (byte)49, (byte)49, (byte)49, (byte)49, (byte)49, (byte)49, (byte)49, (byte)49, (byte)49, (byte)49, (byte)49  };
	
	public static void main(String[] args) throws Exception {
		RSALibrary r = new RSALibrary();
		r.generateKeys();
		
		/* Read  public key*/
		Path path = Paths.get("./public.key");
		byte[] bytes = Files.readAllBytes(path);
		//Public key is stored in x509 format
		X509EncodedKeySpec keyspec = new X509EncodedKeySpec(bytes);
		KeyFactory keyfactory = KeyFactory.getInstance("RSA");
		PublicKey publicKey = keyfactory.generatePublic(keyspec);
		
		/* Read private key */
		path = Paths.get("./private.key");
		byte[] bytes2 = Files.readAllBytes(path);
		//Private key is stored in PKCS8 format
		PKCS8EncodedKeySpec keyspec2 = new PKCS8EncodedKeySpec(bytes2);
		KeyFactory keyfactory2 = KeyFactory.getInstance("RSA");
		PrivateKey privateKey = keyfactory2.generatePrivate(keyspec2);
		
		// Encrypt plaintext with the Public Key
		byte[] ciphertext = r.encrypt(plaintext, publicKey);
		if (ciphertext != null) {
			//Print the resulting ciphertext
			System.out.println("Ciphertext:");
			for (int i = 0; i < ciphertext.length; ++i)
				System.out.print(ciphertext[i] + " ");
			System.out.println();
			// Decrypt ciphertext with the Private Key 
			byte[] text = r.decrypt(ciphertext, privateKey);
			// Print the resulting plain text
			System.out.println("Plaintext:");
			for (int i = 0; i < text.length; ++i)
				System.out.print(text[i] + " ");
			System.out.println();
		}
		
		// Verify the results
		if (r.verify(plaintext, r.sign(plaintext, privateKey), publicKey))
			System.out.println("True");
		else
			System.out.println("False");
	}
}
