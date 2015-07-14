import java.security.*;
import javax.crypto.*;

public class AESKey{
	private final static int BIT = 128;
	private KeyGenerator keyGen;
	private Key key;
	
	public AESKey() {
		try {
			keyGen = KeyGenerator.getInstance("AES");
			generateKey();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}
	public byte[] AESencrypt(byte[] plainText,Key k)throws Exception
	{	
		Cipher cipher=Cipher.getInstance("AES");
		cipher.init(Cipher.ENCRYPT_MODE,k);
		byte[] cipherText=cipher.doFinal(plainText);	
		return cipherText;	
	}
	
	
	public String AESdecrypt(byte[] t,Key k)throws Exception
	{
		Cipher cipher=Cipher.getInstance("AES");	
		cipher.init(Cipher.DECRYPT_MODE,k);
		byte[] newPlainText = cipher.doFinal(t);	
		return new String(newPlainText,"UTF8");		
	}
	private void generateKey() {
		keyGen.init(BIT);
		key = keyGen.generateKey();
	}
	
	public Key getKey(){
		return key;
	}
}
