package aladdin.capi.ansi.pkcs11.mac;
import aladdin.capi.*; 
import aladdin.capi.pkcs11.*; 
import aladdin.capi.ansi.keys.*; 
import aladdin.pkcs11.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////////
// Алгоритм вычисления имитовставки CBC-MAC DES
///////////////////////////////////////////////////////////////////////////////
public class CBCMAC_DES extends aladdin.capi.pkcs11.Mac
{
	// конструктор
	public CBCMAC_DES(Applet applet) { this(applet, 4); }
            
	// конструктор
	public CBCMAC_DES(Applet applet, int macSize) 
    
        // сохранить переданные параметры
        { super(applet); this.macSize = macSize; } private final int macSize; 
    
	// параметры алгоритма
	@Override protected Mechanism getParameters(Session session)
	{ 
        // вернуть параметры алгоритма
        return new Mechanism(API.CKM_DES_MAC); 
	}
    // тип ключа
    @Override public final SecretKeyFactory keyFactory() { return DES.INSTANCE; } 
	// размер ключа в байтах
	@Override public final int[] keySizes() { return new int[]{8}; }
    
	// размер хэш-значения в байтах
	@Override public int macSize() { return macSize; } 
	// размер блока в байтах
	@Override public int blockSize() { return 8; } 
    
    // завершить выработку имитовставки
    @Override public int finish(byte[] buf, int bufOff) throws IOException
    {
        // указать требуемый размер
        if (buf == null) return macSize; byte[] mac = new byte[4];

	    // завершить хэширование данных
	    if (total() != 0) super.finish(mac, 0);

        // скопировать хэш-значение
        System.arraycopy(mac, 0, buf, bufOff, macSize); return macSize; 
    }
}
