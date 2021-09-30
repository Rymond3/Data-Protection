
public class Test {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		SymmetricCipher s = new SymmetricCipher();
		byte[] input = new byte[] { (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54, 
				(byte)55, (byte)56, (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52,
				(byte)53, (byte)54 };
		
		byte[] key = new byte[] { (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54, 
				(byte)55, (byte)56, (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52,
				(byte)53, (byte)54 };
		
		try {
			// Encrypt the input with the key and decrypt it again
			byte[] plaintext = s.decryptCBC(s.encryptCBC(input, key), key);
			
			// Print the resulting plaintext to prove it is equal to the input
			for (int i = 0; i < plaintext.length; ++i)
				System.out.print(plaintext[i] + " ");
			System.out.println(" ");
				
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
