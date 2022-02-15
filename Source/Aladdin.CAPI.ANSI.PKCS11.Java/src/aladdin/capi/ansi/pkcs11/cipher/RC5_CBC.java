package aladdin.capi.ansi.pkcs11.cipher;
import aladdin.pkcs11.*; 
import aladdin.pkcs11.jni.*; 
import aladdin.capi.*; 
import aladdin.capi.pkcs11.*;
import aladdin.capi.ansi.keys.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования RC5 в режиме CBC
///////////////////////////////////////////////////////////////////////////////
public class RC5_CBC extends aladdin.capi.pkcs11.BlockMode
{
	// размер ключей и число раундов
	private final int[] keySizes; private final int rounds; 
    // параметры режима
    private final CipherMode.CBC parameters; 

	// конструктор
	public RC5_CBC(Applet applet, int rounds, 
        int[] keySizes, CipherMode.CBC parameters) throws IOException
	{ 
		// сохранить переданные параметры
		super(applet, PaddingMode.NONE); this.rounds = rounds; this.parameters = parameters;
        
        // указать допустимые размеры ключей
        if (keySizes != null) this.keySizes = keySizes; 
        else {
            // получить информацию алгоритма
            MechanismInfo info = applet.getAlgorithmInfo(API.CKM_RC5_CBC); 
            
            // указать допустимые размеры ключей
            this.keySizes = KeySizes.range(info.minKeySize(), info.maxKeySize()); 
        }
	}
	// параметры алгоритма
	@Override public Mechanism getParameters(Session sesssion)
	{
        // указать параметры алгоритма
        CK_RC5_CBC_PARAMS rc5Parameters = new CK_RC5_CBC_PARAMS(
            parameters.blockSize() / 2, rounds, parameters.iv()
        ); 
        // вернуть параметры алгоритма
        return new Mechanism(API.CKM_RC5_CBC, rc5Parameters); 
	}
    // тип ключа
    @Override public final SecretKeyFactory keyFactory() { return RC5.INSTANCE; } 
	// размер ключа в байтах
	@Override public final int[] keySizes() { return keySizes; }
    
	// размер блока
	@Override public final int blockSize() { return parameters.blockSize(); } 
    
	// режим алгоритма
	@Override public CipherMode mode() { return parameters; }
} 
