package aladdin.capi.ansi.pkcs11.pbe;
import aladdin.capi.ansi.pkcs11.*;
import aladdin.capi.ansi.keys.*;
import aladdin.capi.pkcs11.*;
import aladdin.capi.pkcs11.Attribute;
import aladdin.capi.pkcs11.pbe.*;
import aladdin.capi.*;
import aladdin.pkcs11.*;
import aladdin.pkcs11.jni.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования по паролю PKCS12 RC2-CBC
///////////////////////////////////////////////////////////////////////////
public class PBESP12_RC2_CBC extends PBESP12
{
    // эффективное число битов ключа и размер ключа
    private int effectiveKeyBits; private int keyLength; 
    
	// конструктор 
	public PBESP12_RC2_CBC(Applet applet, long algID, byte[] salt, int iterations)
	{
        // сохранить переданные параметры
        super(applet, algID, salt, iterations); 

        // определить эффективное число битов ключа
        if (algID == API.CKM_PBE_SHA1_RC2_40_CBC ) effectiveKeyBits =  40; else 
        if (algID == API.CKM_PBE_SHA1_RC2_128_CBC) effectiveKeyBits = 128; 
            
        // при ошибке выбросить исключение
        else throw new UnsupportedOperationException(); 
        
        // вычислить размер ключа
        keyLength = (effectiveKeyBits + 7) / 8; 
	}
    // размер блока алгоритма
	@Override public final int blockSize() { return 8; } 
	// фабрика ключа
	@Override protected SecretKeyFactory deriveKeyFactory()
    {
        // фабрика ключа
        return new RC2(new int[] {keyLength}); 
    }
	// создать алгоритм шифрования
	@Override protected aladdin.capi.Cipher createCipher(byte[] iv) throws IOException
    {
        // указать параметры алгоритма
        Mechanism mechanism = new Mechanism(API.CKM_RC2_CBC_PAD, 
            new CK_RC2_CBC_PARAMS(effectiveKeyBits, iv)
        ); 
        // создать алгоритм шифрования
        aladdin.capi.Cipher cipher = Creator.createCipher(
            applet().provider(), applet(), mechanism, keyLength
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
            new Attribute(API.CKA_VALUE_LEN, keyLength  ) 
        }; 
    } 
}
