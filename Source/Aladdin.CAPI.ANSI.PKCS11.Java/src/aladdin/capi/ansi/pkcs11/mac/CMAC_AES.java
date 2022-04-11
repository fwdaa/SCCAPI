package aladdin.capi.ansi.pkcs11.mac;
import aladdin.pkcs11.*; 
import aladdin.capi.*;
import aladdin.capi.pkcs11.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм вычисления имитовставки CMAC AES
///////////////////////////////////////////////////////////////////////////////
public class CMAC_AES extends aladdin.capi.pkcs11.Mac
{
    // размер ключей и размер имитовставки
    private final int[] keySizes; private final int macSize; 
    
	// конструктор
	public CMAC_AES(Applet applet, int[] keySizes) throws IOException 
    { 
        // сохранить переданные параметры
        this(applet, keySizes, 16); 
    } 
	// конструктор
	public CMAC_AES(Applet applet, int[] keySizes, int macSize) throws IOException
    { 
        // сохранить переданные параметры
        super(applet); this.macSize = macSize; 
        
        // указать допустимые размеры ключей
        if (keySizes != null) this.keySizes = keySizes; 
        else {
            // получить информацию алгоритма
            MechanismInfo info = applet.getAlgorithmInfo(API.CKM_AES_CMAC); 
            
            // указать допустимые размеры ключей
            this.keySizes = KeySizes.range(info.minKeySize(), info.maxKeySize(), 8); 
        }
    } 
	// параметры алгоритма
	@Override protected Mechanism getParameters(Session session)
	{ 
        // вернуть параметры алгоритма
        return new Mechanism(API.CKM_AES_CMAC); 
	}
    // тип ключа
    @Override public final SecretKeyFactory keyFactory() 
    { 
        // вернуть тип ключа
        return new aladdin.capi.ansi.keys.AES(keySizes); 
    } 
	// размер хэш-значения в байтах
	@Override public int macSize() { return macSize; } 
	// размер блока в байтах
	@Override public int blockSize() { return 16; } 

    // завершить выработку имитовставки
    @Override public int finish(byte[] buf, int bufOff) throws IOException
    {
        // указать требуемый размер
        if (buf == null) return macSize(); 

	    // завершить хэширование данных
	    byte[] mac = new byte[16]; super.finish(mac, 0);

        // скопировать хэш-значение
        System.arraycopy(mac, 0, buf, bufOff, macSize()); return macSize(); 
    }
}
