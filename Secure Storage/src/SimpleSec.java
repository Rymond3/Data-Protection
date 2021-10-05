import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public class SimpleSec {

	public static void main(String[] args) {
		parseCommand(args);
	}
	
	public static void parseCommand(String[] args) {
		try {
			switch(args[0]) {
			case "g":
				if (args.length == 1)
					generateKeys();
				else
					throw new IllegalArgumentException("Option 'g' doesn't take arguments.");				
				break;
			case "e":
				if (args.length == 3)
					encrypt(args[1], args[2]);
				else
					throw new IllegalArgumentException("Option 'e' requires the source and destination filenames.");				
				break;
			case "d":
				if (args.length == 3)
					decrypt(args[1], args[2]);
				else
					throw new IllegalArgumentException("Option 'd' requires the source and destination filenames.");
				break;
			default:
				throw new IllegalArgumentException("Invalid commands. Commands available: g (generate keys), e (encrypt file), d (decrypt file).");
			}
		}
		catch (ArrayIndexOutOfBoundsException e) {
			System.err.println("Invalid number of arguments: " + e.getMessage());
			System.err.println("Usage: java SimpleSec command [sourceFile] [destinationFile]");
		}
		catch (IllegalArgumentException e) {
			System.err.println("Invalid arguments: " + e.getMessage());
			System.err.println("Usage: java SimpleSec command [sourceFile] [destinationFile]");
		}
	}
	
	public static void generateKeys() {
		RSALibrary rsa = new RSALibrary();
		
		try {
			rsa.generateKeys();
			System.out.println("Key pair generated successfuly!");
		} catch (Exception e) {
			System.err.println("Error while encrypting the key: " + e.getMessage());
		}
	}
	
	public static void encrypt(String sourceFile, String destinationFile) {
		try {
			Path path = Paths.get("./public.key");
			byte[] bytes = Files.readAllBytes(path);
			//Public key is stored in x509 format
			X509EncodedKeySpec keyspec = new X509EncodedKeySpec(bytes);
			KeyFactory keyfactory = KeyFactory.getInstance("RSA");
			PublicKey publicKey = keyfactory.generatePublic(keyspec);
			
			RSALibrary rsa = new RSALibrary();
			byte[] encryptionresult = rsa.encrypt(sourceFile, publicKey);
			
			if (encryptionresult != null) {
				PKCS8EncodedKeySpec keyspec2 = new PKCS8EncodedKeySpec(rsa.decryptPrivateKey());
				KeyFactory keyfactory2 = KeyFactory.getInstance("RSA");
				PrivateKey privateKey = keyfactory2.generatePrivate(keyspec2);
				
				byte[] result = rsa.sign(encryptionresult, privateKey);
				
				FileOutputStream out = new FileOutputStream(destinationFile);
				out.write(encryptionresult);
		        out.write(result);
		        out.close();
		        
		        System.out.println("Encryption performed successfully!");
			}
			else
				System.err.println("Error while encrypting the file.");
		} catch(IOException e) {
			System.err.println("Couldn't read the file " + sourceFile + ": " + e.getMessage());
		} catch (Exception e) {
			System.err.println("Error while encrypting the file: " + e.getMessage());
		}
	}
	
	public static void decrypt(String sourceFile, String destinationFile) {
		try {
			Path path = Paths.get(sourceFile);
			byte[] bytes = Files.readAllBytes(path);
			
			path = Paths.get("./public.key");
			byte[] bytes2 = Files.readAllBytes(path);
			//Public key is stored in x509 format
			X509EncodedKeySpec keyspec = new X509EncodedKeySpec(bytes2);
			KeyFactory keyfactory = KeyFactory.getInstance("RSA");
			PublicKey publicKey = keyfactory.generatePublic(keyspec);
			
			byte[] cipherresult = Arrays.copyOfRange(bytes, 0, bytes.length-128);
	    	byte[] signature = Arrays.copyOfRange(bytes, bytes.length-128, bytes.length);
			
			RSALibrary rsa = new RSALibrary();
	
			if (rsa.verify(cipherresult, signature, publicKey)) {
				byte[] key = rsa.decryptPrivateKey();
				
				//Private key is stored in PKCS8 format
				PKCS8EncodedKeySpec keyspec2 = new PKCS8EncodedKeySpec(key);
				KeyFactory keyfactory2 = KeyFactory.getInstance("RSA");
				PrivateKey privateKey = keyfactory2.generatePrivate(keyspec2);
				
				byte[] result = rsa.decrypt(cipherresult, privateKey);
				if (result != null) {
					FileOutputStream out = new FileOutputStream(destinationFile);
			        out.write(result);
			        out.close();
			        
			        System.out.println("Decryption performed successfully!");
				}
				else
					System.err.println("Error while decrypting the file.");
			}
			else
				System.out.println("Signature doesn't match!");
			
		} catch (IOException e) {
			System.err.println("Couldn't read the file " + sourceFile + ": " + e.getMessage());
		} catch (Exception e) {
			System.err.println("Error while decrypting the file: " + e.getMessage());
		}
	}
}
