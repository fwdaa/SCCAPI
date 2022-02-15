package aladdin.capi.ansi.pkcs11.pbe;
import aladdin.capi.ansi.pkcs11.*;
import aladdin.capi.pkcs11.*;
import aladdin.capi.pkcs11.Attribute;
import aladdin.capi.pkcs11.pbe.*;
import aladdin.capi.ansi.keys.*; 
import aladdin.pkcs11.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования по паролю PBES1 DES-CBC
///////////////////////////////////////////////////////////////////////////
public class PBES1_DES_CBC extends PBES1
{
	// конструктор 
	public PBES1_DES_CBC(Applet applet, long algID, byte[] salt, int iterations)
	{
        // сохранить переданные параметры
        super(applet, algID, salt, iterations, DES.INSTANCE); 
	}
    // размер блока алгоритма
	@Override public final int blockSize() { return 8; } 
	// размер ключа
	@Override protected int keyLength() { return 8; }  
	// размер синхропосылки
	@Override protected int ivLength() { return 8; }  
    
	// создать алгоритм шифрования
	@Override protected aladdin.capi.Cipher createCipher(byte[] iv) throws IOException
    {
        // указать параметры алгоритма
        Mechanism mechanism = new Mechanism(API.CKM_DES_CBC_PAD, iv); 
        
        // создать алгоритм шифрования
        aladdin.capi.Cipher cipher = Creator.createCipher(
            applet().provider(), applet(), mechanism, 0
        ); 
        // проверить наличие алгоритма
        if (cipher == null) throw new UnsupportedOperationException(); return cipher; 
    }
	// атрибуты ключа
	@Override public Attribute[] getKeyAttributes() 
    { 
        // дополнительные атрибуты ключа
        return new Attribute[] {new Attribute(API.CKA_KEY_TYPE, API.CKK_DES)}; 
    } 
}
