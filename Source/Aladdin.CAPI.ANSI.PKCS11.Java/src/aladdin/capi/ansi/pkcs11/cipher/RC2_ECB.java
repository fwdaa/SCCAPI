package aladdin.capi.ansi.pkcs11.cipher;
import aladdin.pkcs11.*; 
import aladdin.capi.*; 
import aladdin.capi.pkcs11.*; 
import aladdin.capi.ansi.keys.*;
import java.io.*; 


///////////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования RC2 в режиме ECB
///////////////////////////////////////////////////////////////////////////////
public class RC2_ECB extends aladdin.capi.pkcs11.BlockMode
{
	// эффективное число битов ключа и размеры ключей
	private final int effectiveKeyBits; private final int[] keySizes; 

	// конструктор
	public RC2_ECB(Applet applet, int effectiveKeyBits, int[] keySizes) throws IOException
	{ 
		// сохранить переданные параметры
		super(applet, PaddingMode.NONE); this.effectiveKeyBits = effectiveKeyBits;
        
        // указать допустимые размеры ключей
        if (keySizes != null) this.keySizes = keySizes; 
        else {
            // получить информацию алгоритма
            MechanismInfo info = applet.getAlgorithmInfo(API.CKM_RC2_ECB); 
            
            // указать допустимые размеры ключей
            this.keySizes = KeySizes.range((info.minKeySize() + 7) / 8, info.maxKeySize() / 8); 
        }
	} 
	// параметры алгоритма
    @Override public Mechanism getParameters(Session sesssion)
	{
		// параметры алгоритма
		return new Mechanism(API.CKM_RC2_ECB, effectiveKeyBits); 
	}
    // тип ключа
    @Override public final SecretKeyFactory keyFactory() { return RC2.INSTANCE; } 
	// размер ключа в байтах
	@Override public final int[] keySizes() { return keySizes; }
	// размер блока
	@Override public final int blockSize() { return 8; } 

	// режим алгоритма
	@Override public CipherMode mode() { return new CipherMode.ECB(); }
} 
