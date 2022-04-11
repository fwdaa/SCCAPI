package aladdin.capi.gost.pkcs11.cipher;
import aladdin.asn1.*; 
import aladdin.capi.*; 
import aladdin.capi.pkcs11.*; 
import aladdin.pkcs11.*;

///////////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования ГОСТ 28147-89 с указанием набора параметров
///////////////////////////////////////////////////////////////////////////////
public class GOST28147_RFC4357 extends aladdin.capi.pkcs11.BlockMode
{
	// параметры ключа и синхропосылка
	private final byte[] encodedOID; private final byte[] iv;

    // конструктор
	public GOST28147_RFC4357(Applet applet, String paramsOID, byte[] iv) 
	{
        // сохранить переданные параметры
		super(applet, PaddingMode.NONE); this.iv = iv; 
        
		// закодировать параметры алгоритма
		encodedOID = new ObjectIdentifier(paramsOID).encoded(); 
	}
	// параметры алгоритма
    @Override
	public Mechanism getParameters(Session session)
	{ 
        // параметры алгоритма
		return new Mechanism(API.CKM_GOST28147, iv); 
	}
	// атрибуты ключа
    @Override public Attribute[] getKeyAttributes(int keySize)
	{ 
		// выделить память для атрибутов
		return new Attribute[] { 

            // указать требуемые атрибуты
            new Attribute(API.CKA_KEY_TYPE, API.CKK_GOST28147), 

            // указать требуемые атрибуты
            new Attribute(API.CKA_GOST28147_PARAMS, encodedOID)
        }; 
	}
	// режим алгоритма
    @Override public CipherMode mode() { return new CipherMode.CFB(iv, 8); }
    
    // тип ключа
    @Override public final SecretKeyFactory keyFactory() 
    { 
        // тип ключа
        return aladdin.capi.gost.keys.GOST.INSTANCE; 
    } 
	// размер блока
	@Override public final int blockSize() { return 8; } 
}; 
