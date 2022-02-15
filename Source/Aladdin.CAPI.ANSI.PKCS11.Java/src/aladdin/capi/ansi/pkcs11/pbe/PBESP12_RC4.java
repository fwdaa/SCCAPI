package aladdin.capi.ansi.pkcs11.pbe;
import aladdin.capi.pkcs11.*;
import aladdin.capi.pkcs11.Attribute;
import aladdin.capi.pkcs11.pbe.*;
import aladdin.capi.ansi.keys.*;
import aladdin.capi.ansi.pkcs11.*;
import aladdin.pkcs11.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования по паролю PKCS12 RC4
///////////////////////////////////////////////////////////////////////////
public class PBESP12_RC4 extends PBESP12
{
    // размер ключа
    private final int keyLength; 
    
	// конструктор 
	public PBESP12_RC4(Applet applet, long algID, byte[] salt, int iterations)
	{
        // сохранить переданные параметры
        super(applet, algID, salt, iterations, RC4.INSTANCE); 
        
        // определить эффективное число битов ключа
        if (algID == API.CKM_PBE_SHA1_RC4_128) keyLength = 16; else 
        if (algID == API.CKM_PBE_SHA1_RC4_40 ) keyLength =  5; 
            
        // при ошибке выбросить исключение
        else throw new UnsupportedOperationException(); 
	}
	// размер ключа
	@Override protected int keyLength() { return keyLength; }  
	// размер синхропосылки
	@Override protected int ivLength() { return 8; }  
    
	// создать алгоритм шифрования
	@Override protected aladdin.capi.Cipher createCipher(byte[] iv) throws IOException
    {
        // указать параметры алгоритма
        Mechanism mechanism = new Mechanism(API.CKM_RC4); 
        
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
            new Attribute(API.CKA_KEY_TYPE , API.CKK_RC4), 
            new Attribute(API.CKA_VALUE_LEN, keyLength     ) 
        }; 
    } 
}
