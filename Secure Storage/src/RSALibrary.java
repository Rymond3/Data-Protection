import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.util.Arrays;
import java.util.Random;
import java.util.Scanner;

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
  public void generateKeys() throws Exception {

    try {
        // Initialize the key pair
        final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
        keyGen.initialize(1024);
            
        KeyPair keys = keyGen.generateKeyPair();
        
        //Encrypt private key
        byte[] encryptedKey = encryptPrivateKey(keys);
        
        // Create Private Key file
        FileOutputStream out = new FileOutputStream(PRIVATE_KEY_FILE);
        out.write(encryptedKey);
        out.close();
        
        // Create Public Key file
        out = new FileOutputStream(PUBLIC_KEY_FILE);
        out.write(keys.getPublic().getEncoded());
        out.close();

        // Handle possible exceptions
	} catch (NoSuchAlgorithmException e) {
		System.out.println("Exception: " + e.getMessage());
		System.exit(-1);
	} catch (IOException e) {
		System.err.println("Unnable to write the key pair: " + e.getMessage());
	}
  }
  
  public byte[] encryptPrivateKey(KeyPair keys) throws Exception {
	  //Get the user written passphrase
	  System.out.print("Introduce a passphrase to encrypt the private key: ");
      Scanner sc = new Scanner(System.in);
      byte[] passphrase = sc.nextLine().getBytes();
      sc.close();
      
      SymmetricCipher s = new SymmetricCipher();
      
      //Use the passphrase to encrypt the private key using AES/CBC
      return s.encryptCBC(keys.getPrivate().getEncoded(), passphrase);
  }
  
  public byte[] decryptPrivateKey() throws IOException, Exception {
	  //Read the encrypted private key
	  Path path = Paths.get(PRIVATE_KEY_FILE);
	  byte[] bytes = Files.readAllBytes(path);
	  
	  //Get the user written passphrase
	  System.out.print("Introduce a passphrase to decrypt the private key: ");
      Scanner sc = new Scanner(System.in);
      byte[] passphrase = sc.nextLine().getBytes();
      sc.close();
      
      SymmetricCipher s = new SymmetricCipher();
      
      //Use the passphrase to decrypt the private key using AES/CBC
      return s.decryptCBC(bytes, passphrase);
  }


  /***********************************************************************************/
  /* Encrypts a plaintext using an RSA public key. */
  /* Arguments: the plaintext and the RSA public key */
  /* Returns a byte array with the ciphertext */
  /***********************************************************************************/
  public byte[] encrypt(String sourceFile, PublicKey key) {
	  byte[] result = null;

      try {
    	  //Read the sourcefile
    	  Path path = Paths.get(sourceFile);
    	  byte[] plaintext = Files.readAllBytes(path);
    	  
    	  SymmetricCipher s = new SymmetricCipher();
    	  
    	  //Create a 16 Bytes random Session Key
    	  Random rd = new Random();
          byte[] sessionKey = new byte[16];
          rd.nextBytes(sessionKey);
          
          //Encrypt the plaintext using AES/CBC and the Session Key
    	  byte[] ciphertext = s.encryptCBC(plaintext, sessionKey);
    	  
    	  // Gets an RSA cipher object
	      final Cipher cipher = Cipher.getInstance(ALGORITHM);
	      cipher.init(Cipher.ENCRYPT_MODE, key);
	      
	      //Encrypt the Session Key using RSA and the public key
	      byte[] cipherkey = cipher.doFinal(sessionKey);
	      
	      //Concatenate the ciphertext and cipherkey
	      ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
	      outputStream.write(ciphertext);
	      outputStream.write(cipherkey);

	      result = outputStream.toByteArray( );
      } catch (IllegalBlockSizeException e) {
    	  System.err.println("Illegal block size: " + e.getMessage());
      }  catch (IOException e) {
    	  System.err.println("Couldn't read the file " + sourceFile+ ": " + e.getMessage());
      } catch (Exception e) {
    	  System.err.println("Error while encrypting the file: " + e.getMessage());
      }
      
      return result;
  }


  /***********************************************************************************/
  /* Decrypts a ciphertext using an RSA private key. */
  /* Arguments: the ciphertext and the RSA private key */
  /* Returns a byte array with the plaintext */
  /***********************************************************************************/
  public byte[] decrypt(byte[] cipherinput, PrivateKey key) throws Exception {

    byte[] plaintext = null;

    try {
    	//Divide into cipherkey (128 Bytes) and ciphertext (rest)
    	byte[] ciphertext = Arrays.copyOfRange(cipherinput, 0, cipherinput.length-128);
    	byte[] cipherkey = Arrays.copyOfRange(cipherinput, cipherinput.length-128, cipherinput.length);
    	
    	// Gets an RSA cipher object
	    final Cipher cipher = Cipher.getInstance(ALGORITHM);
	    cipher.init(Cipher.DECRYPT_MODE, key);
	    
	    //Decrypt the session key using RSA and the private key
	    byte[] sessionkey = cipher.doFinal(cipherkey);
	    
	    //Decrypt the text using AES/CBC and the session key
	    SymmetricCipher s = new SymmetricCipher();
	    plaintext = s.decryptCBC(ciphertext, sessionkey);   
    } catch (IllegalBlockSizeException e) {
        System.err.println("Illegal block size: " + e.getMessage());
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
	  
    } catch (Exception e) {
    	System.err.println("Error while signing the file: " + e.getMessage());
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
	
    } catch (Exception e) {
    	System.err.println("Error while verifying the file: " + e.getMessage());
    }

	return result;
  }
	
}

