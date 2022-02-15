package aladdin.capi.ansi.pkcs11.mac;
import aladdin.pkcs11.*; 
import aladdin.pkcs11.jni.*; 
import aladdin.capi.*;
import aladdin.capi.ansi.keys.*; 
import aladdin.capi.pkcs11.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм вычисления имитовставки CBC-MAC RC2
///////////////////////////////////////////////////////////////////////////////
public class CBCMAC_RC2_GENERAL extends aladdin.capi.pkcs11.Mac
{
	// эффективное число битов ключа, размер ключей и размер имитовставки
	private final int effectiveKeyBits; private final int[] keySizes; private final int macSize; 

	// конструктор
	public CBCMAC_RC2_GENERAL(Applet applet, int effectiveKeyBits, 
        int[] keySizes, int macSize) throws IOException
	{ 
		// сохранить переданные параметры
		super(applet); this.effectiveKeyBits = effectiveKeyBits; this.macSize = macSize;
        
        // указать допустимые размеры ключей
        if (keySizes != null) this.keySizes = keySizes; 
        else {
            // получить информацию алгоритма
            MechanismInfo info = applet.getAlgorithmInfo(API.CKM_RC2_MAC_GENERAL); 
            
            // указать допустимые размеры ключей
            this.keySizes = KeySizes.range((info.minKeySize() + 7) / 8, info.maxKeySize() / 8); 
        }
	} 
	// параметры алгоритма
	@Override protected Mechanism getParameters(Session session)
	{ 
        // указать параметры алгоритма
        CK_RC2_MAC_GENERAL_PARAMS rc2Paramaters = 
            new CK_RC2_MAC_GENERAL_PARAMS(effectiveKeyBits, macSize); 
        
        // вернуть параметры алгоритма
        return new Mechanism(API.CKM_RC2_MAC_GENERAL, rc2Paramaters); 
	}
    // тип ключа
    @Override public final SecretKeyFactory keyFactory() { return RC2.INSTANCE; } 
	// размер ключа в байтах
	@Override public final int[] keySizes() { return keySizes; }
    
	// размер хэш-значения в байтах
	@Override public int macSize() { return macSize; } 
	// размер блока в байтах
	@Override public int blockSize() { return 8; } 
    
    // завершить выработку имитовставки
    @Override public int finish(byte[] buf, int bufOff) throws IOException
    {
        // указать требуемый размер
        if (buf == null) return macSize; byte[] mac = new byte[macSize];

	    // завершить хэширование данных
	    if (total() != 0) super.finish(mac, 0);

        // скопировать хэш-значение
        System.arraycopy(mac, 0, buf, bufOff, macSize); return macSize; 
    }
}
