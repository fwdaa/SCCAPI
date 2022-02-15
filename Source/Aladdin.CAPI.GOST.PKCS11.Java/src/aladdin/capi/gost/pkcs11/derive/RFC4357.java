package aladdin.capi.gost.pkcs11.derive;
import aladdin.asn1.*; 
import aladdin.capi.pkcs11.*;
import aladdin.pkcs11.*;

///////////////////////////////////////////////////////////////////////////////
// Алгоритм смены ключа RFC4357
///////////////////////////////////////////////////////////////////////////////
public class RFC4357 extends aladdin.capi.pkcs11.KeyDerive
{
    // закодированный идентификатор таблицы подстановок
    private final byte[] encodedOID; 
    
	// конструктор
	public RFC4357(Applet applet, String sboxOID)
	{ 	 
		// закодировать параметры алгоритма
		super(applet); encodedOID = new ObjectIdentifier(sboxOID).encoded();
    } 
	// параметры алгоритма
	@Override protected Mechanism getParameters(Session sesssion, byte[] random)
    {
        // параметры алгоритма
        return new Mechanism(API.CKM_KDF_4357, random); 
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
}
