package aladdin.capi.ansi.pkcs11.rsa;
import aladdin.math.*; 
import aladdin.capi.*;
import aladdin.capi.pkcs11.*;
import aladdin.pkcs11.*;
import java.math.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Открытый ключ RSA
///////////////////////////////////////////////////////////////////////////
public class PublicKey extends aladdin.capi.PublicKey implements aladdin.capi.ansi.rsa.IPublicKey
{
    // способ кодирования чисел
    private static final Endian ENDIAN = Endian.BIG_ENDIAN; 
    
	private final BigInteger modulus;           // параметр N
	private final BigInteger publicExponent;	// параметр E
    
	// атрибуты открытого ключа
	public static Attribute[] getAttributes(aladdin.capi.ansi.rsa.IPublicKey publicKey)
    {
        // закодировать параметры открытого ключа
        byte[] modulus        = Convert.fromBigInteger(publicKey.getModulus       (), ENDIAN); 
        byte[] publicExponent = Convert.fromBigInteger(publicKey.getPublicExponent(), ENDIAN);
        
        // создать набор атрибутов
        return new Attribute[] { new Attribute(API.CKA_KEY_TYPE, API.CKK_RSA),

            // указать идентификаторы параметров
            new Attribute(API.CKA_MODULUS        , modulus       ),
            new Attribute(API.CKA_PUBLIC_EXPONENT, publicExponent) 
        }; 
    }
    // конструктор
	public PublicKey(aladdin.capi.pkcs11.Provider provider, SessionObject object) throws IOException
    {
        // сохранить переданные параметры
        super(provider.getKeyFactory(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA)); 
        
		// получить атрибуты ключа
		Attributes keyAttributes = provider.getKeyAttributes(object, 
            new Attribute(API.CKA_MODULUS        , byte[].class), 
            new Attribute(API.CKA_PUBLIC_EXPONENT, byte[].class) 
        ); 
        // раскодировать значение параметров
        modulus = Convert.toBigInteger(
            (byte[])keyAttributes.get(API.CKA_MODULUS).value(), ENDIAN
        );
        publicExponent = Convert.toBigInteger(
            (byte[])keyAttributes.get(API.CKA_PUBLIC_EXPONENT).value(), ENDIAN
        );
    }
    // параметры ключа
    @Override public IParameters parameters()
    {
        // параметры ключа
        return new aladdin.capi.ansi.rsa.Parameters(modulus.bitLength(), publicExponent);     
    }
	@Override public final BigInteger getModulus        () { return modulus;        }
	@Override public final BigInteger getPublicExponent () { return publicExponent;	}
}
