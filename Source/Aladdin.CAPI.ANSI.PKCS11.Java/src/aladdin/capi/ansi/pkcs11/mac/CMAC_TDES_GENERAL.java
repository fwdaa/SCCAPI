package aladdin.capi.ansi.pkcs11.mac;
import aladdin.pkcs11.*; 
import aladdin.capi.*;
import aladdin.capi.pkcs11.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм вычисления имитовставки CMAC TDES
///////////////////////////////////////////////////////////////////////////////
public class CMAC_TDES_GENERAL extends aladdin.capi.pkcs11.Mac
{
    // размер ключей и размер имитовставки
    private final int[] keySizes; private final int macSize;
    
	// конструктор
	public CMAC_TDES_GENERAL(Applet applet, int[] keySizes, int macSize) throws IOException
    { 
        // сохранить переданные параметры
        super(applet); this.keySizes = keySizes; this.macSize = macSize; 
    } 
	// параметры алгоритма
	@Override protected Mechanism getParameters(Session session)
	{ 
        // вернуть параметры алгоритма
        return new Mechanism(API.CKM_DES3_CMAC_GENERAL, macSize); 
	}
    // тип ключа
    @Override public final SecretKeyFactory keyFactory() 
    { 
        // вернуть тип ключа
        return new aladdin.capi.ansi.keys.TDES(keySizes); 
    } 
	// размер хэш-значения в байтах
	@Override public int macSize() { return macSize; } 
	// размер блока в байтах
	@Override public int blockSize() { return 8; } 
}
