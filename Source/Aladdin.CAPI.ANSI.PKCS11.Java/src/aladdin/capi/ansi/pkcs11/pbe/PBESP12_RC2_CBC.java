package aladdin.capi.ansi.pkcs11.pbe;
import aladdin.capi.ansi.keys.*;
import aladdin.capi.ansi.pkcs11.*;
import aladdin.capi.pkcs11.*;
import aladdin.capi.pkcs11.Attribute;
import aladdin.capi.pkcs11.pbe.*;
import aladdin.pkcs11.*;
import aladdin.pkcs11.jni.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования по паролю PKCS12 RC2-CBC
///////////////////////////////////////////////////////////////////////////
public class PBESP12_RC2_CBC extends PBESP12
{
    // эффективное число битов ключа
    private int effectiveKeyBits; 
    
	// конструктор 
	public PBESP12_RC2_CBC(Applet applet, long algID, byte[] salt, int iterations)
	{
        // сохранить переданные параметры
        super(applet, algID, salt, iterations, RC2.INSTANCE); 

        // определить эффективное число битов ключа
        if (algID == API.CKM_PBE_SHA1_RC2_40_CBC ) effectiveKeyBits =  40; else 
        if (algID == API.CKM_PBE_SHA1_RC2_128_CBC) effectiveKeyBits = 128; 
            
        // при ошибке выбросить исключение
        else throw new UnsupportedOperationException(); 
	}
    // размер блока алгоритма
	@Override public final int blockSize() { return 8; } 
	// размер ключа
	@Override protected int keyLength() { return (effectiveKeyBits + 7) / 8; }  
	// размер синхропосылки
	@Override protected int ivLength() { return 8; }  
    
	// создать алгоритм шифрования
	@Override protected aladdin.capi.Cipher createCipher(byte[] iv) throws IOException
    {
        // указать параметры алгоритма
        Mechanism mechanism = new Mechanism(API.CKM_RC2_CBC_PAD, 
            new CK_RC2_CBC_PARAMS(effectiveKeyBits, iv)
        ); 
        // создать алгоритм шифрования
        aladdin.capi.Cipher cipher = Creator.createCipher(
            applet().provider(), applet(), mechanism, keyLength()
        ); 
        // проверить наличие алгоритма
        if (cipher == null) throw new UnsupportedOperationException(); return cipher; 
    }
	// атрибуты ключа
	@Override public Attribute[] getKeyAttributes() 
    { 
        // дополнительные атрибуты ключа
        return new Attribute[] {
            new Attribute(API.CKA_KEY_TYPE , API.CKK_RC2), 
            new Attribute(API.CKA_VALUE_LEN, keyLength()   ) 
        }; 
    } 
}
