import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;


public class RSALibrary {

  // String to hold name of the encryption algorithm.
  public final String ALGORITHM = "RSA";

  //String to hold the name of the private key file.
  public final String PRIVATE_KEY_FILE = "./private.key";

  // String to hold name of the public key file.
  public final String PUBLIC_KEY_FILE = "./public.key";

  /***********************************************************************************/
   /* Generates an RSA key pair (a public and a private key) of 1024 bits length */
   /* Stores the keys in the files defined by PUBLIC_KEY_FILE and PRIVATE_KEY_FILE */
   /* Throws IOException */
  /***********************************************************************************/
  public void generateKeys() throws IOException {

    try {

    	// Initialize the key pair
      final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
      keyGen.initialize(1024);
            
      KeyPair keys = keyGen.generateKeyPair();
      
      // Create Public Key file
      FileOutputStream out = new FileOutputStream(PUBLIC_KEY_FILE);
      out.write(keys.getPublic().getEncoded());
      out.close();
            
      // Create Private Key file
      out = new FileOutputStream(PRIVATE_KEY_FILE);
      out.write(keys.getPrivate().getEncoded());
      out.close();

      // Handle possible exceptions
	} catch (NoSuchAlgorithmException e) {
		System.out.println("Exception: " + e.getMessage());
		System.exit(-1);
	}
  }


  /***********************************************************************************/
  /* Encrypts a plaintext using an RSA public key. */
  /* Arguments: the plaintext and the RSA public key */
  /* Returns a byte array with the ciphertext */
  /***********************************************************************************/
  public byte[] encrypt(byte[] plaintext, PublicKey key) {

    byte[] ciphertext = null;

    try {
    	// Gets an RSA cipher object
	    final Cipher cipher = Cipher.getInstance(ALGORITHM);
	    cipher.init(Cipher.ENCRYPT_MODE, key);
	    
	    ciphertext = cipher.doFinal(plaintext);
    } catch (IllegalBlockSizeException e) {
      System.err.println("Illegal block size: " + e.getMessage());
    } catch (Exception e) {
        e.printStackTrace();
    }
    return ciphertext;
  }


  /***********************************************************************************/
  /* Decrypts a ciphertext using an RSA private key. */
  /* Arguments: the ciphertext and the RSA private key */
  /* Returns a byte array with the plaintext */
  /***********************************************************************************/
  public byte[] decrypt(byte[] ciphertext, PrivateKey key) {

    byte[] plaintext = null;

    try {
    	// Gets an RSA cipher object
	    final Cipher cipher = Cipher.getInstance(ALGORITHM);
	    cipher.init(Cipher.DECRYPT_MODE, key);
	    
	    plaintext = cipher.doFinal(ciphertext);
    } catch (IllegalBlockSizeException e) {
        System.err.println("Illegal block size: " + e.getMessage());
    } catch (Exception ex) {
      ex.printStackTrace();
    }

    return plaintext;
  }

  /***********************************************************************************/
  /* Signs a plaintext using an RSA private key. */
  /* Arguments: the plaintext and the RSA private key */
  /* Returns a byte array with the signature */
  /***********************************************************************************/
  public byte[] sign(byte[] plaintext, PrivateKey key) {
		
    byte[] signedInfo = null;

    try {

	  // Gets a Signature object
      Signature signature = Signature.getInstance("SHA1withRSA");

	  // Initialize the signature object with the private key
	  signature.initSign(key);
	
	  // Set plaintext as the bytes to be signed
	  signature.update(plaintext);
	
	  // Sign the plaintext and obtain the signature (signedInfo)
	  signedInfo = signature.sign();

    } catch (Exception ex) {
      ex.printStackTrace();
    }

	return signedInfo;
  }
	
  /***********************************************************************************/
  /* Verifies a signature over a plaintext */
  /* Arguments: the plaintext, the signature to be verified (signed) 
  /* and the RSA public key */
  /* Returns TRUE if the signature was verified, false if not */
  /***********************************************************************************/
  public boolean verify(byte[] plaintext, byte[] signed, PublicKey key) {

	boolean result = false;

    try {

 	 // Gets a Signature object
     Signature signature = Signature.getInstance("SHA1withRSA");

	  // Initialize the signature object with the public key
	  signature.initVerify(key);

	  // Set plaintext as the bytes to be verified
	  signature.update(plaintext);

	  // Verify the signature (signed). Store the outcome in the boolean result
	  result = signature.verify(signed);
	
    } catch (Exception ex) {
      ex.printStackTrace();
    }

	return result;
  }
	
}

