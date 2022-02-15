package aladdin.capi.ansi.pkcs11.cipher;
import aladdin.pkcs11.*; 
import aladdin.capi.*; 
import aladdin.capi.pkcs11.*; 
import aladdin.capi.ansi.keys.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования AES в режиме ECB
///////////////////////////////////////////////////////////////////////////////
public class AES_ECB extends aladdin.capi.pkcs11.BlockMode
{
    // размер ключей
    private final int[] keySizes;
    
	// конструктор
	public AES_ECB(Applet applet, int[] keySizes) throws IOException
    { 
        // сохранить переданные параметры
        super(applet, PaddingMode.NONE); 
        
        // указать допустимые размеры ключей
        if (keySizes != null) this.keySizes = keySizes; 
        else {
            // получить информацию алгоритма
            MechanismInfo info = applet.getAlgorithmInfo(API.CKM_AES_ECB); 
            
            // указать допустимые размеры ключей
            this.keySizes = KeySizes.range(info.minKeySize(), info.maxKeySize(), 8); 
        }
    }
    // параметры алгоритма
	@Override public Mechanism getParameters(Session sesssion)
	{
		// параметры алгоритма
		return new Mechanism(API.CKM_AES_ECB); 
	}
    // тип ключа
    @Override public final SecretKeyFactory keyFactory() { return AES.INSTANCE; } 
	// размер ключа в байтах
	@Override public final int[] keySizes() { return keySizes; }
	// размер блока
	@Override public final int blockSize() { return 16; } 

	// режим алгоритма
	@Override public CipherMode mode() { return new CipherMode.ECB(); }
} 
