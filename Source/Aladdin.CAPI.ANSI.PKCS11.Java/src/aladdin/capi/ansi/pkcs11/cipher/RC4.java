package aladdin.capi.ansi.pkcs11.cipher;
import aladdin.pkcs11.*; 
import aladdin.capi.*;
import aladdin.capi.pkcs11.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования RC4
///////////////////////////////////////////////////////////////////////////////
public class RC4 extends aladdin.capi.pkcs11.Cipher
{
	// допустимый размер ключей
	private final int[] keySizes; 

	// конструктор
	public RC4(Applet applet, int[] keySizes) throws IOException
	{ 	
        // указать допустимые размеры ключей
        super(applet); if (keySizes != null) this.keySizes = keySizes; 
        else {
            // получить информацию алгоритма
            MechanismInfo info = applet.getAlgorithmInfo(API.CKM_RC4); 
            
            // указать допустимые размеры ключей
            this.keySizes = KeySizes.range((info.minKeySize() + 7) / 8, info.maxKeySize() / 8); 
        }
    } 
	// параметры алгоритма
	@Override public Mechanism getParameters(Session sesssion) 
    {
    	// параметры алгоритма
		return new Mechanism(API.CKM_RC4); 
	}
    // тип ключа
    @Override public final SecretKeyFactory keyFactory() 
    { 
        // тип ключа
        return new aladdin.capi.ansi.keys.RC4(keySizes); 
    } 
} 
