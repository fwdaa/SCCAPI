package aladdin.capi.ansi.pkcs11.mac;
import aladdin.capi.*;
import aladdin.capi.pkcs11.*; 
import aladdin.pkcs11.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////////
// Алгоритм вычисления имитовставки CBC-MAC DES
///////////////////////////////////////////////////////////////////////////////
public class CBCMAC_DES_GENERAL extends aladdin.capi.pkcs11.Mac
{
    // размер имитовставки
    private final int macSize; 
    
	// конструктор
	public CBCMAC_DES_GENERAL(Applet applet, int macSize) 
    {
        // сохранить переданные параметры
        super(applet); this.macSize = macSize; 
    } 
	// параметры алгоритма
	@Override protected Mechanism getParameters(Session session)
	{ 
        // вернуть параметры алгоритма
        return new Mechanism(API.CKM_DES_MAC_GENERAL, macSize); 
	}
    // тип ключа
    @Override public final SecretKeyFactory keyFactory() 
    { 
        // вернуть тип ключа
        return aladdin.capi.ansi.keys.DES.INSTANCE; 
    } 
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
