package aladdin.capi.ansi.pkcs11.mac;
import aladdin.pkcs11.*; 
import aladdin.capi.*;
import aladdin.capi.pkcs11.*; 
import aladdin.capi.ansi.keys.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм вычисления имитовставки CMAC AES
///////////////////////////////////////////////////////////////////////////////
public class CMAC_AES_GENERAL extends aladdin.capi.pkcs11.Mac
{
    // размер ключей и размер имитовставки
    private final int[] keySizes; private final int macSize;
    
	// конструктор
	public CMAC_AES_GENERAL(Applet applet, int[] keySizes, int macSize) throws IOException
    { 
        // сохранить переданные параметры
        super(applet); this.macSize = macSize; 
        
        // указать допустимые размеры ключей
        if (keySizes != null) this.keySizes = keySizes; 
        else {
            // получить информацию алгоритма
            MechanismInfo info = applet.getAlgorithmInfo(API.CKM_AES_CMAC_GENERAL); 
            
            // указать допустимые размеры ключей
            this.keySizes = KeySizes.range(info.minKeySize(), info.maxKeySize(), 8); 
        }
    } 
	// параметры алгоритма
	@Override protected Mechanism getParameters(Session session)
	{ 
        // вернуть параметры алгоритма
        return new Mechanism(API.CKM_AES_CMAC_GENERAL, macSize); 
	}
    // тип ключа
    @Override public final SecretKeyFactory keyFactory() { return AES.INSTANCE; } 
	// размер ключа в байтах
	@Override public final int[] keySizes() { return keySizes; }
    
	// размер хэш-значения в байтах
	@Override public int macSize() { return macSize; } 
	// размер блока в байтах
	@Override public int blockSize() { return 16; } 
}
