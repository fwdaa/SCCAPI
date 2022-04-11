package aladdin.capi.ansi.pkcs11.cipher;
import aladdin.pkcs11.*; 
import aladdin.pkcs11.jni.*; 
import aladdin.capi.*; 
import aladdin.capi.pkcs11.*; 
import aladdin.capi.ansi.keys.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования RC5 в режиме ECB
///////////////////////////////////////////////////////////////////////////////
public class RC5_ECB extends aladdin.capi.pkcs11.BlockMode
{
    // размер блока, число раундов и размер ключей
    private final int blockSize; private final int rounds; private final int[] keySizes; 

	// конструктор
	public RC5_ECB(Applet applet, int blockSize, int rounds, int[] keySizes) throws IOException
	{ 
		// сохранить переданные параметры
		super(applet, PaddingMode.NONE); this.blockSize = blockSize; this.rounds = rounds;
        
        // указать допустимые размеры ключей
        if (keySizes != null) this.keySizes = keySizes; 
        else {
            // получить информацию алгоритма
            MechanismInfo info = applet.getAlgorithmInfo(API.CKM_RC5_ECB); 
            
            // указать допустимые размеры ключей
            this.keySizes = KeySizes.range(info.minKeySize(), info.maxKeySize()); 
        }
	}
	// параметры алгоритма
	@Override public Mechanism getParameters(Session sesssion)
	{
        // указать параметры алгоритма
        CK_RC5_PARAMS rc5Parameters = new CK_RC5_PARAMS(blockSize / 2, rounds); 
                
        // вернуть параметры алгоритма
        return new Mechanism(API.CKM_RC5_ECB, rc5Parameters); 
    }
    // тип ключа
    @Override public final SecretKeyFactory keyFactory() { return new RC5(keySizes); } 
	// размер блока
	@Override public final int blockSize() { return blockSize; } 
    
	// режим алгоритма
	@Override public CipherMode mode() { return new CipherMode.ECB(); }
} 
