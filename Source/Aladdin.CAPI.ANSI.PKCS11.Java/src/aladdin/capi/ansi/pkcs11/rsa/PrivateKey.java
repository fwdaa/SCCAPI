package aladdin.capi.ansi.pkcs11.rsa;
import aladdin.math.*; 
import aladdin.capi.*;
import aladdin.capi.pkcs11.*;
import aladdin.pkcs11.*;
import java.math.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Личный ключ RSA
///////////////////////////////////////////////////////////////////////////
public class PrivateKey extends aladdin.capi.pkcs11.PrivateKey 
    implements aladdin.capi.ansi.rsa.IPrivateKey
{
    // способ кодирования чисел
    private static final Endian ENDIAN = Endian.BIG_ENDIAN; 
    
    // атрибуты ключа
    private Attributes keyAttributes; 
    
	private final BigInteger modulus;           // параметр N
	private final BigInteger publicExponent;	// параметр E
	private final BigInteger privateExponent;   // параметр D
	private final BigInteger prime1;            // параметр P
	private final BigInteger prime2;            // параметр Q
	private final BigInteger exponent1;         // параметр D (mod P-1)
	private final BigInteger exponent2;         // параметр D (mod Q-1)
	private final BigInteger coefficient;       // параметр Q^{-1}(mod P)
    
	// атрибуты личного ключа
	public static Attribute[] getAttributes(
        aladdin.capi.ansi.rsa.IPrivateKey privateKey) throws IOException
    {
        // закодировать параметры открытого ключа
        byte[] modulus         = Convert.fromBigInteger(privateKey.getModulus        (), ENDIAN); 
        byte[] publicExponent  = Convert.fromBigInteger(privateKey.getPublicExponent (), ENDIAN);
        byte[] privateExponent = Convert.fromBigInteger(privateKey.getPrivateExponent(), ENDIAN);
        byte[] prime1          = Convert.fromBigInteger(privateKey.getPrimeP         (), ENDIAN);
        byte[] prime2          = Convert.fromBigInteger(privateKey.getPrimeQ         (), ENDIAN);
        byte[] exponent1       = Convert.fromBigInteger(privateKey.getPrimeExponentP (), ENDIAN);
        byte[] exponent2       = Convert.fromBigInteger(privateKey.getPrimeExponentQ (), ENDIAN);
        byte[] coefficient     = Convert.fromBigInteger(privateKey.getCrtCoefficient (), ENDIAN);
        
        // создать набор атрибутов
        return new Attribute[] { new Attribute(API.CKA_KEY_TYPE, API.CKK_RSA),

            // указать идентификаторы параметров
            new Attribute(API.CKA_MODULUS,          modulus        ), 
            new Attribute(API.CKA_PUBLIC_EXPONENT,  publicExponent ), 
            new Attribute(API.CKA_PRIVATE_EXPONENT, privateExponent), 
            new Attribute(API.CKA_PRIME_1,          prime1         ), 
            new Attribute(API.CKA_PRIME_2,          prime2         ), 
            new Attribute(API.CKA_EXPONENT_1,       exponent1      ), 
            new Attribute(API.CKA_EXPONENT_2,       exponent2      ), 
            new Attribute(API.CKA_COEFFICIENT,      coefficient    ) 
        }; 
    }
	// конструктор 
	public PrivateKey(aladdin.capi.pkcs11.Provider provider, SecurityObject scope, 
        SessionObject object, aladdin.capi.ansi.rsa.IPublicKey publicKey) throws IOException
    {
        // сохранить переданные параметры
        super(provider, scope, publicKey.keyOID()); 
        
        // сохранить параметры открытого ключа
        modulus = publicKey.getModulus(); publicExponent = publicKey.getPublicExponent(); 
        
	    // получить атрибуты ключа
	    keyAttributes = provider.getKeyAttributes(object); 
        
        // указать атрибуты открытого ключа
        Attributes publicAttributes = new Attributes(
            new Attribute(API.CKA_MODULUS,          Convert.fromBigInteger(modulus       , ENDIAN)), 
            new Attribute(API.CKA_PUBLIC_EXPONENT,  Convert.fromBigInteger(publicExponent, ENDIAN)) 
        ); 
        // добавить атрибуты в список
        keyAttributes = keyAttributes.join(publicAttributes); 
            
        // при возможности извлечения значения
        if ((Byte)keyAttributes.get(API.CKA_EXTRACTABLE).value() != API.CK_FALSE && 
            (Byte)keyAttributes.get(API.CKA_SENSITIVE  ).value() == API.CK_FALSE)
        {
            // указать требуемые атрибуты
            Attribute[] attributes = new Attribute[] {
                new Attribute(API.CKA_PRIVATE_EXPONENT, byte[].class) 
            }; 
            // получить атрибуты ключа
            attributes = object.getAttributes(attributes); 
            
            // добавить атрибут в список
            keyAttributes = keyAttributes.join(attributes); 

            // указать значения атрибутов по умолчанию
            attributes = new Attribute[] {
                new Attribute(API.CKA_PRIME_1,     byte[].class), 
                new Attribute(API.CKA_PRIME_2,     byte[].class),
                new Attribute(API.CKA_EXPONENT_1,  byte[].class), 
                new Attribute(API.CKA_EXPONENT_2,  byte[].class), 
                new Attribute(API.CKA_COEFFICIENT, byte[].class) 
            }; 
            // получить атрибуты ключа
            attributes = object.getSafeAttributes(attributes); 
            
            // добавить атрибуты в список
            keyAttributes = keyAttributes.join(attributes); 
        }
        // при отсутствии на смарт-карте
        if ((Byte)keyAttributes.get(API.CKA_TOKEN).value() == API.CK_FALSE)
        {
            // проверить наличие значения
            if (keyAttributes.get(API.CKA_PRIVATE_EXPONENT) == null)
            {
                // при ошибке выбросить исключение
                throw new aladdin.pkcs11.Exception(API.CKR_KEY_UNEXTRACTABLE); 
            }
        }
        // проверить наличие атрибута
        if (keyAttributes.get(API.CKA_PRIVATE_EXPONENT) == null) privateExponent = null; 
        else {
            // раскодировать значение параметров
            privateExponent = Convert.toBigInteger(
                (byte[])keyAttributes.get(API.CKA_PRIVATE_EXPONENT).value(), ENDIAN
            );
        }
        // проверить наличие атрибута
        if (keyAttributes.get(API.CKA_PRIME_1) == null) prime1 = null; 
        else {
            // раскодировать значение параметров
            prime1 = Convert.toBigInteger(
                (byte[])keyAttributes.get(API.CKA_PRIME_1).value(), ENDIAN
            );
        }
        // проверить наличие атрибута
        if (keyAttributes.get(API.CKA_PRIME_2) == null) prime2 = null; 
        else {
            // раскодировать значение параметров
            prime2 = Convert.toBigInteger(
                (byte[])keyAttributes.get(API.CKA_PRIME_2).value(), ENDIAN
            );
        }
        // при наличии атрибута
        if (keyAttributes.get(API.CKA_EXPONENT_1) != null)
        {
            // получить значение атрибута
            exponent1 = Convert.toBigInteger(
                (byte[])keyAttributes.get(API.CKA_EXPONENT_1).value(), ENDIAN
            );
        }
        // вычислить значение параметра
        else exponent1 = (prime1 != null) ? privateExponent.mod(prime1) : null; 
        
        // при наличии атрибута
        if (keyAttributes.get(API.CKA_EXPONENT_2) != null)
        {
            // получить значение атрибута
            exponent2 = Convert.toBigInteger(
                (byte[])keyAttributes.get(API.CKA_EXPONENT_2).value(), ENDIAN
            );
        }
        // вычислить значение параметра
        else exponent2 = (prime2 != null) ? privateExponent.mod(prime2) : null; 
        
        // при наличии атрибута
        if (keyAttributes.get(API.CKA_COEFFICIENT) != null)
        {
            // получить значение атрибута
            coefficient = Convert.toBigInteger(
                (byte[])keyAttributes.get(API.CKA_COEFFICIENT).value(), ENDIAN
            );
        }
        // вычислить значение параметра
        else coefficient = (prime1 != null && prime2 != null) ? prime2.modInverse(prime1) : null;
    }
    @Override public final IParameters parameters() 
    {
        // параметры ключа
        return new aladdin.capi.ansi.rsa.Parameters(modulus.bitLength(), publicExponent);     
    }
	@Override public final BigInteger getModulus        () { return modulus;           }
	@Override public final BigInteger getPublicExponent () { return publicExponent;	}
    
	@Override public final BigInteger getPrivateExponent() throws IOException
    { 
        // проверить наличие значения
        if (privateExponent != null) return privateExponent;	

        // при ошибке выбросить исключение
        throw new aladdin.pkcs11.Exception(API.CKR_KEY_UNEXTRACTABLE); 
    }
	@Override public final BigInteger getPrimeP() throws IOException
    { 
        // проверить наличие значения
        if (prime1 != null) return prime1;

        // при ошибке выбросить исключение
        throw new aladdin.pkcs11.Exception(API.CKR_KEY_UNEXTRACTABLE); 
    }
	@Override public final BigInteger getPrimeQ() throws IOException
    { 
        // проверить наличие значения
        if (prime2 != null) return prime2;

        // при ошибке выбросить исключение
        throw new aladdin.pkcs11.Exception(API.CKR_KEY_UNEXTRACTABLE); 
    }
	@Override public final BigInteger getPrimeExponentP() throws IOException
    { 
        // проверить наличие значения
        if (exponent1 != null) return exponent1;

        // при ошибке выбросить исключение
        throw new aladdin.pkcs11.Exception(API.CKR_KEY_UNEXTRACTABLE); 
    }
	@Override public final BigInteger getPrimeExponentQ() throws IOException
    { 
        // проверить наличие значения
        if (exponent2 != null) return exponent2;

        // при ошибке выбросить исключение
        throw new aladdin.pkcs11.Exception(API.CKR_KEY_UNEXTRACTABLE); 
    }
	@Override public final BigInteger getCrtCoefficient() throws IOException
    { 
        // проверить наличие значения
        if (coefficient != null) return coefficient;

        // при ошибке выбросить исключение
        throw new aladdin.pkcs11.Exception(API.CKR_KEY_UNEXTRACTABLE); 
    }
    // атрибуты ключа
    @Override protected Attributes keyAttributes() { return keyAttributes; } 
}
