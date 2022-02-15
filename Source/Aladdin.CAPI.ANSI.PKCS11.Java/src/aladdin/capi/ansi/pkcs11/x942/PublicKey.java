package aladdin.capi.ansi.pkcs11.x942;
import aladdin.math.*; 
import aladdin.capi.pkcs11.*;
import aladdin.pkcs11.*;
import java.math.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Открытый ключ DH
///////////////////////////////////////////////////////////////////////////
public class PublicKey extends aladdin.capi.PublicKey implements aladdin.capi.ansi.x942.IPublicKey
{
    // способ кодирования чисел
    private static final Endian ENDIAN = Endian.BIG_ENDIAN; 
    
    // параметры ключа
    private final BigInteger p; private final BigInteger q;
    private final BigInteger g; private final BigInteger y;  
    
	// атрибуты открытого ключа
	public static Attribute[] getAttributes(aladdin.capi.ansi.x942.IPublicKey publicKey)
    {
        // преобразовать тип параметров
        aladdin.capi.ansi.x942.IParameters parameters = 
            (aladdin.capi.ansi.x942.IParameters)publicKey.parameters(); 
        
        // закодировать параметры открытого ключа
        byte[] p = Convert.fromBigInteger(parameters.getP(), ENDIAN); 
        byte[] q = Convert.fromBigInteger(parameters.getQ(), ENDIAN);
        byte[] g = Convert.fromBigInteger(parameters.getG(), ENDIAN);        
        
        // закодировать значение ключа
        byte[] y = Convert.fromBigInteger(publicKey.getY(), ENDIAN);
        
        // создать набор атрибутов
        return new Attribute[] { new Attribute(API.CKA_KEY_TYPE, API.CKK_X9_42_DH),

            // указать параметры
            new Attribute(API.CKA_PRIME, p), new Attribute(API.CKA_SUBPRIME, q),  
            new Attribute(API.CKA_BASE , g), new Attribute(API.CKA_VALUE   , y)  
        }; 
    }
    // конструктор
	public PublicKey(Provider provider, SessionObject object) throws IOException 
    {
        // сохранить переданные параметры
        super(provider.getKeyFactory(aladdin.asn1.ansi.OID.X942_DH_PUBLIC_KEY)); 
        
        // получить атрибуты ключа
		Attributes keyAttributes = provider.getKeyAttributes(object, 
            new Attribute(API.CKA_PRIME   , byte[].class), 
            new Attribute(API.CKA_SUBPRIME, byte[].class), 
            new Attribute(API.CKA_BASE    , byte[].class), 
            new Attribute(API.CKA_VALUE   , byte[].class) 
        ); 
        // раскодировать значение параметров
        p = Convert.toBigInteger(
            (byte[])keyAttributes.get(API.CKA_PRIME).value(), ENDIAN
        );
        q = Convert.toBigInteger(
            (byte[])keyAttributes.get(API.CKA_SUBPRIME).value(), ENDIAN
        );
        g = Convert.toBigInteger(
            (byte[])keyAttributes.get(API.CKA_BASE).value(), ENDIAN
        );
        y = Convert.toBigInteger(
            (byte[])keyAttributes.get(API.CKA_VALUE).value(), ENDIAN
        );
    }
    // параметры ключа
    @Override public aladdin.capi.ansi.x942.IParameters parameters()
    {
        // параметры ключа
        return new aladdin.capi.ansi.x942.Parameters(p, q, g);     
    }
    // значение ключа
	@Override public final BigInteger getY() { return y; }
}
