package aladdin.capi.gost.pkcs11.mac;
import aladdin.asn1.*; 
import aladdin.capi.*; 
import aladdin.capi.pkcs11.*; 
import aladdin.pkcs11.*;

///////////////////////////////////////////////////////////////////////////////
// Алгоритм вычисления имитовставки ГОСТ 28147-89
///////////////////////////////////////////////////////////////////////////////
public class GOST28147 extends aladdin.capi.pkcs11.Mac
{
	// параметры ключа и синхропосылка
	private final byte[] encodedOID; private final byte[] iv; 

    // конструктор
	public GOST28147(Applet applet, String paramsOID, byte[] iv) 
	{
		// сохранить переданные параметры
		super(applet); this.iv = iv; 
            
		// закодировать параметры алгоритма
		encodedOID = new ObjectIdentifier(paramsOID).encoded(); 
	}
	// параметры алгоритма
    @Override
	public Mechanism getParameters(Session session)
	{ 
        // параметры алгоритма
		return new Mechanism(API.CKM_GOST28147_MAC, iv); 
	}
	// атрибуты ключа
    @Override
	protected Attribute[] getKeyAttributes(int keySize)
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
	// размер хэш-значения в байтах
	@Override public final int macSize() { return 4; } 
	// размер блока в байтах
	@Override public final int blockSize() { return 8; } 
};
