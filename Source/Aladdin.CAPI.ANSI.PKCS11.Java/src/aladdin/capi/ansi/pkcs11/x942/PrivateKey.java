package aladdin.capi.ansi.pkcs11.x942;
import aladdin.math.*; 
import aladdin.capi.*;
import aladdin.capi.pkcs11.*;
import aladdin.pkcs11.*;
import java.math.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Личный ключ DH
///////////////////////////////////////////////////////////////////////////
public class PrivateKey extends aladdin.capi.pkcs11.PrivateKey 
    implements aladdin.capi.ansi.x942.IPrivateKey
{
    // способ кодирования чисел
    private static final Endian ENDIAN = Endian.BIG_ENDIAN; 
    
    // атрибуты ключа и секретное значение
    private Attributes keyAttributes; private final BigInteger x;  
    // параметры ключа
    private final aladdin.capi.ansi.x942.IParameters parameters; 
    
	// атрибуты личного ключа
	public static Attribute[] getAttributes(
        aladdin.capi.ansi.x942.IPrivateKey privateKey) throws IOException
    {
        // преобразовать тип параметров
        aladdin.capi.ansi.x942.IParameters parameters = 
            (aladdin.capi.ansi.x942.IParameters)privateKey.parameters(); 
        
        // закодировать параметры личного ключа
        byte[] p = Convert.fromBigInteger(parameters.getP(), ENDIAN); 
        byte[] q = Convert.fromBigInteger(parameters.getQ(), ENDIAN);
        byte[] g = Convert.fromBigInteger(parameters.getG(), ENDIAN);        
        
        // закодировать значение ключа
        byte[] x = Convert.fromBigInteger(privateKey.getX(), ENDIAN);
        
        // создать набор атрибутов
        return new Attribute[] { new Attribute(API.CKA_KEY_TYPE, API.CKK_X9_42_DH),

            // указать параметры
            new Attribute(API.CKA_PRIME, p), new Attribute(API.CKA_SUBPRIME, q),  
            new Attribute(API.CKA_BASE , g), new Attribute(API.CKA_VALUE   , x)  
        }; 
    }
	// конструктор 
	public PrivateKey(aladdin.capi.pkcs11.Provider provider, SecurityObject scope, 
        SessionObject object, aladdin.capi.ansi.x942.IPublicKey publicKey) throws IOException
    {
        // сохранить переданные параметры
        super(provider, scope, publicKey.keyOID()); 
        
        // получить атрибуты ключа
        keyAttributes = provider.getKeyAttributes(object);
        
        // сохранить параметры открытого ключа
        parameters = (aladdin.capi.ansi.x942.IParameters)publicKey.parameters(); 
        
        // указать атрибуты открытого ключа
        Attributes publicAttributes = new Attributes(
            new Attribute(API.CKA_PRIME   , Convert.fromBigInteger(parameters.getP(), ENDIAN)), 
            new Attribute(API.CKA_SUBPRIME, Convert.fromBigInteger(parameters.getQ(), ENDIAN)), 
            new Attribute(API.CKA_BASE    , Convert.fromBigInteger(parameters.getG(), ENDIAN)) 
        ); 
        // добавить атрибуты в список
        keyAttributes = keyAttributes.join(publicAttributes); 
            
        // при возможности извлечения значения
        if ((Byte)keyAttributes.get(API.CKA_EXTRACTABLE).value() != API.CK_FALSE && 
            (Byte)keyAttributes.get(API.CKA_SENSITIVE  ).value() == API.CK_FALSE)
        {
            // указать требуемые атрибуты
            Attribute[] attributes = new Attribute[] {
                new Attribute(API.CKA_VALUE, byte[].class) 
            }; 
            // получить атрибуты ключа
            attributes = object.getAttributes(attributes); 
            
            // добавить атрибут в список
            keyAttributes = keyAttributes.join(attributes); 
        }
        // при отсутствии на смарт-карте
        if ((Byte)keyAttributes.get(API.CKA_TOKEN).value() == API.CK_FALSE)
        {
            // проверить наличие значения
            if (keyAttributes.get(API.CKA_VALUE) == null)
            {
                // при ошибке выбросить исключение
                throw new aladdin.pkcs11.Exception(API.CKR_KEY_UNEXTRACTABLE); 
            }
        }
        // проверить наличие атрибута
        if (keyAttributes.get(API.CKA_VALUE) == null) x = null; 
        else {
            // раскодировать значение параметров
            x = Convert.toBigInteger(
                (byte[])keyAttributes.get(API.CKA_VALUE).value(), ENDIAN
            );
        }
    }
    // параметры ключа
    @Override public final IParameters parameters() { return parameters; }
    
    // значение ключа
	@Override public final BigInteger getX() throws IOException
    { 
        // проверить наличие значения
        if (x != null) return x;

        // при ошибке выбросить исключение
        throw new aladdin.pkcs11.Exception(API.CKR_KEY_UNEXTRACTABLE); 
    }
    // атрибуты ключа
    @Override protected Attributes keyAttributes() { return keyAttributes; } 
}
