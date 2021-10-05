import java.io.FileDescriptor;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import javax.crypto.*;
import java.security.InvalidKeyException;

public class SymmetricCipher {

	byte[] byteKey;
	SymmetricEncryption s;
	SymmetricEncryption d;
	int blockSize = 16; //16 Bytes = 128 bits
	
	// Initialization Vector (fixed)
	
	byte[] iv = new byte[] { (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54, 
		(byte)55, (byte)56, (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52,
		(byte)53, (byte)54};

    /*************************************************************************************/
	/* Constructor method */
    /*************************************************************************************/
	public void SymmetricCipher() {
	}

    /*************************************************************************************/
	/* Method to encrypt using AES/CBC/PKCS5 */
    /*************************************************************************************/
	public byte[] encryptCBC (byte[] input, byte[] byteKey) throws Exception {
		
		/* Generate the plaintext with padding */
		
		//Number of bytes used for padding
		int paddingBytes = blockSize - (input.length % blockSize); 
		
		//Initialize the destination of the input plus padding
		byte[] destination = new byte[input.length + paddingBytes]; 
		
		//Copy the input to the destination array
		System.arraycopy(input, 0, destination, 0, input.length); 
		
		//Add the padding to the destination
		for (int i = 0; i < paddingBytes; ++i)
			destination[input.length + i] = (byte)paddingBytes; 
		
		/* Generate the ciphertext */
		
		//Initialize the destination of xoring the cipherblocks
		byte[] xor = new byte[blockSize];
		
		//Initialize the array used for performing the streaming
		byte[] previous = new byte[blockSize];
		
		//Initialize the resulting ciphertext
		byte[] ciphertext = new byte[destination.length];
		
		//Initialize the cipherblock encryptor
		s = new SymmetricEncryption(byteKey);
		
		//Iterate the plaintext by cipherblocks
		for (int i = 0; i < destination.length; i += blockSize) {
			//Xor the plaintext with the previous stream or iv
			for (int j = 0; j < blockSize; ++j) {
				if (i == 0)
					xor[j] = (byte)(iv[j] ^ destination[j+i]);
				else
					xor[j] = (byte)(previous[j] ^ destination[j+i]);
			}
			
			//Encrypt the result of the xor
			previous = s.encryptBlock(xor);
			
			//Save the result to ciphertext
			System.arraycopy(previous, 0, ciphertext, i, blockSize);
		}	
		
		return ciphertext;
	}
	
	/*************************************************************************************/
	/* Method to decrypt using AES/CBC/PKCS5 */
    /*************************************************************************************/
	
	
	public byte[] decryptCBC (byte[] input, byte[] byteKey) throws Exception {
		
		/* Generate the plaintext */
		
		//Initialize the destination of decrypting the ciphertext
		byte[] decrypted = new byte[input.length]; 
		
		//Initialize the destination of xoring the cipherblocks
		byte[] xor = new byte[blockSize];
		
		//Initialize the array used for handling the ciphertext block by block
		byte[] block = new byte[blockSize];
		
		//Initialize the destination of decrypting the ciphertext
		byte[] aes = new byte[blockSize];
		
		//Initialize the array used for performing the streaming
		byte[] previous = new byte[blockSize];
		
		//Initialize the cipherblock decryptor
		d = new SymmetricEncryption(byteKey);
		
		//Iterate the ciphertext by cipherblocks
		for (int i = 0; i < input.length; i += blockSize) {
			//Copy a cipherblock
			System.arraycopy(input, i, block, 0, blockSize);
			
			//Decrypt the ciphertext
			aes = d.decryptBlock(block);
			
			//Xor the plaintext with the previous stream or iv
			for (int j = 0; j < blockSize; ++j) {
				if (i == 0)
					xor[j] = (byte)(iv[j] ^ aes[j]);
				else
					xor[j] = (byte)(previous[j] ^ aes[j]);
			}
			
			//Save the cipherblock for performing the stream
			System.arraycopy(block, 0, previous, 0, blockSize);
			
			//Save the result to decrypted
			System.arraycopy(xor, 0, decrypted, i, blockSize);
		}
		
		/* Eliminate the padding */
		
		//Get the value of the last Byte
		byte paddingBytes = decrypted[decrypted.length-1];
		
		//Set the size of the plaintext without padding
		byte[] finalplaintext = new byte[decrypted.length - paddingBytes];
		
		//Copy the decrypted text to the destination without the padding
		System.arraycopy(decrypted, 0, finalplaintext, 0, finalplaintext.length); 
		
		return finalplaintext;
	}
	
}

