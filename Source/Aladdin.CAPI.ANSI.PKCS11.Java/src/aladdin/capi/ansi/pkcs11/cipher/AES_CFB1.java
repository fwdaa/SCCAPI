package aladdin.capi.ansi.pkcs11.cipher;
import aladdin.capi.*;
import aladdin.pkcs11.*;
import aladdin.capi.pkcs11.*;
import aladdin.capi.ansi.keys.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования AES в режиме CFB (1-бит)
///////////////////////////////////////////////////////////////////////////////
public class AES_CFB1 extends aladdin.capi.pkcs11.Cipher
{
	// допустимый размер ключей и синхропосылка
	private final int[] keySizes; private final byte[] iv; 

	// конструктор
	public AES_CFB1(Applet applet, int[] keySizes, byte[] iv) throws IOException
	{ 	
        // указать допустимые размеры ключей
        super(applet); this.iv = iv; if (keySizes != null) this.keySizes = keySizes; 
        else {
            // получить информацию алгоритма
            MechanismInfo info = applet.getAlgorithmInfo(API.CKM_AES_CFB1); 
            
            // указать допустимые размеры ключей
            this.keySizes = KeySizes.range(info.minKeySize(), info.maxKeySize(), 8); 
        }
    } 
	// параметры алгоритма
	@Override public Mechanism getParameters(Session sesssion) 
    {
    	// параметры алгоритма
		return new Mechanism(API.CKM_AES_CFB1, iv); 
	}
    // тип ключа
    @Override public final SecretKeyFactory keyFactory() { return new AES(keySizes); } 
}
