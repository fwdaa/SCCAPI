package aladdin.capi.gost.pkcs11.cipher;
import aladdin.asn1.*; 
import aladdin.capi.*; 
import aladdin.capi.pkcs11.*; 
import aladdin.pkcs11.*;

///////////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования ГОСТ 28147-89 в режиме простой замены
///////////////////////////////////////////////////////////////////////////////
public class GOST28147_ECB extends aladdin.capi.pkcs11.BlockMode
{
	// параметры ключа
	private final byte[] encodedOID; 

    // конструктор
	public GOST28147_ECB(Applet applet, String sboxOID) 
	{
        // сохранить переданные параметры
		super(applet, PaddingMode.NONE); 
        
		// закодировать параметры алгоритма
        encodedOID = new ObjectIdentifier(sboxOID).encoded(); 
	}
	// параметры алгоритма
    @Override
	public Mechanism getParameters(Session sesssion)
	{
		// параметры алгоритма
		return new Mechanism(API.CKM_GOST28147_ECB); 
	}
	// атрибуты ключа
    @Override
	public Attribute[] getKeyAttributes(int keySize)
	{ 
		// выделить память для атрибутов
		return new Attribute[] { 

            // указать требуемые атрибуты
            new Attribute(API.CKA_KEY_TYPE, API.CKK_GOST28147), 

            // указать требуемые атрибуты
            new Attribute(API.CKA_GOST28147_PARAMS, encodedOID)
        }; 
	}
    // тип ключа
    @Override public final SecretKeyFactory keyFactory() 
    { 
        // тип ключа
        return aladdin.capi.gost.keys.GOST.INSTANCE; 
    } 
	// размер блока
	@Override public final int blockSize() { return 8; } 
    
	// режим алгоритма
	@Override public CipherMode mode() { return new CipherMode.ECB(); }
}; 
