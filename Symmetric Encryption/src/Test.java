
public class Test {

	public static void main(String[] args) {
		SymmetricCipher s = new SymmetricCipher();
		byte[] input = new byte[] { (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54, 
				(byte)55, (byte)56, (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52,
				(byte)53, (byte)54 };
		
		byte[] key = new byte[] { (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54, 
				(byte)55, (byte)56, (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52,
				(byte)53, (byte)54 };
		
		try {
			byte[] ciphertext = s.encryptCBC(input, key);
			
			System.out.println("Encrypted text: ");
			for (int i = 0; i < ciphertext.length; ++i)
				System.out.print(ciphertext[i] + " ");
			System.out.println();
			
			byte[] plaintext = s.decryptCBC(ciphertext, key);
			
			System.out.println("Decrypted text: ");
			for (int i = 0; i < plaintext.length; ++i)
				System.out.print(plaintext[i] + " ");
			System.out.println();
				
		} catch (Exception e) {
			System.err.println("Error while performing the CBC encryption/decryption: " + e.getMessage());
		}
	}

}
