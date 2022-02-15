package aladdin.capi.ansi.pkcs11.mac;
import aladdin.pkcs11.*; 
import aladdin.pkcs11.jni.*; 
import aladdin.capi.*;
import aladdin.capi.pkcs11.*; 
import aladdin.capi.ansi.keys.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм вычисления имитовставки CBC-MAC RC5
///////////////////////////////////////////////////////////////////////////////
public class CBCMAC_RC5_GENERAL extends aladdin.capi.pkcs11.Mac
{
    // размер ключей и размер имитовставки
    private final int[] keySizes; private final int macSize; 
	// размер блока и число раундов
	private final int blockSize; private final int rounds; 

	// конструктор
    public CBCMAC_RC5_GENERAL(Applet applet, int blockSize, 
        int rounds, int[] keySizes, int macSize) throws IOException
	{ 
		// сохранить переданные параметры
		super(applet); this.blockSize = blockSize; this.rounds = rounds; this.macSize = macSize;
        
        // указать допустимые размеры ключей
        if (keySizes != null) this.keySizes = keySizes; 
        else {
            // получить информацию алгоритма
            MechanismInfo info = applet.getAlgorithmInfo(API.CKM_RC5_MAC_GENERAL); 
            
            // указать допустимые размеры ключей
            this.keySizes = KeySizes.range(info.minKeySize(), info.maxKeySize()); 
        }
	}
	// параметры алгоритма
	@Override protected Mechanism getParameters(Session session)
	{ 
        // указать параметры алгоритма
        CK_RC5_MAC_GENERAL_PARAMS rc5Parameters = 
            new CK_RC5_MAC_GENERAL_PARAMS(blockSize / 2, rounds, macSize); 
        
        // вернуть параметры алгоритма
        return new Mechanism(API.CKM_RC5_MAC_GENERAL, rc5Parameters); 
    }
    // тип ключа
    @Override public final SecretKeyFactory keyFactory() { return RC5.INSTANCE; } 
	// размер ключа в байтах
	@Override public final int[] keySizes() { return keySizes; }
    
	// размер хэш-значения в байтах
	@Override public int macSize() { return macSize; } 
	// размер блока в байтах
	@Override public int blockSize() { return blockSize; } 
    
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
