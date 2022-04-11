package aladdin.capi.ansi.pkcs11.cipher;
import aladdin.pkcs11.*; 
import aladdin.pkcs11.jni.*; 
import aladdin.capi.*; 
import aladdin.capi.pkcs11.*; 
import aladdin.capi.ansi.keys.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования RC2 в режиме CBC
///////////////////////////////////////////////////////////////////////////////
public class RC2_CBC extends aladdin.capi.pkcs11.BlockMode
{
	// эффективное число битов ключа и размеры ключей
    private final int effectiveKeyBits; private final int[] keySizes; 
    // параметры режима
    private final CipherMode.CBC parameters;

	// конструктор
	public RC2_CBC(Applet applet, int effectiveKeyBits, 
        int[] keySizes, CipherMode.CBC parameters) throws IOException
	{ 
		// сохранить переданные параметры
		super(applet, PaddingMode.NONE); this.parameters = parameters; 
        
        // проверить размер блока
        if (parameters.blockSize() != 8) throw new UnsupportedOperationException(); 
        
		// сохранить переданные параметры
		this.effectiveKeyBits = effectiveKeyBits; 
        
        // указать допустимые размеры ключей
        if (keySizes != null) this.keySizes = keySizes; 
        else {
            // получить информацию алгоритма
            MechanismInfo info = applet.getAlgorithmInfo(API.CKM_RC2_CBC); 
            
            // указать допустимые размеры ключей
            this.keySizes = KeySizes.range((info.minKeySize() + 7) / 8, info.maxKeySize() / 8); 
        }
	} 
	// параметры алгоритма
	@Override public Mechanism getParameters(Session sesssion)
	{
        // указать параметры алгоритма
        CK_RC2_CBC_PARAMS rc2Parameters = new CK_RC2_CBC_PARAMS(
            effectiveKeyBits, parameters.iv()
        ); 
        // вернуть параметры алгоритма
        return new Mechanism(API.CKM_RC2_CBC, rc2Parameters); 
    }
    // тип ключа
    @Override public final SecretKeyFactory keyFactory() { return new RC2(keySizes); } 
	// размер блока
	@Override public final int blockSize() { return 8; } 

	// режим алгоритма
	@Override public CipherMode mode() { return parameters; }
} 
