package aladdin.capi.ansi.pkcs11.x962;
import aladdin.math.*; 
import aladdin.capi.*;
import aladdin.capi.pkcs11.*;
import aladdin.pkcs11.*;
import java.math.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Личный ключ EC/ECDSA
///////////////////////////////////////////////////////////////////////////
public class PrivateKey extends aladdin.capi.pkcs11.PrivateKey 
    implements aladdin.capi.ansi.x962.IPrivateKey
{
    // способ кодирования чисел
    private static final Endian ENDIAN = Endian.BIG_ENDIAN; 
    
    // атрибуты ключа и секретное значение
    private Attributes keyAttributes; private final BigInteger d;  
    // параметры ключа
    private final aladdin.capi.ansi.x962.IParameters parameters; 
    
	// атрибуты личного ключа
	public static Attribute[] getAttributes(
        aladdin.capi.ansi.x962.IPrivateKey privateKey, long flags) throws IOException
    {
        // преобразовать тип параметров
        aladdin.capi.ansi.x962.IParameters parameters = 
            (aladdin.capi.ansi.x962.IParameters)privateKey.parameters(); 
        
        // создать атрибут параметров
        Attribute parametersAttribute = PublicKey.getParametersAttribute(parameters, flags); 
        
        // закодировать значение ключа
        byte[] d = Convert.fromBigInteger(privateKey.getS(), ENDIAN);
        
        // указать атрибут значения
        Attribute valueAttribute = new Attribute(API.CKA_VALUE, d); 
        
        // создать набор атрибутов
        return new Attribute[] { new Attribute(API.CKA_KEY_TYPE, API.CKK_EC),

            // указать параметры
            parametersAttribute, valueAttribute
        }; 
    }
	// конструктор 
	public PrivateKey(aladdin.capi.pkcs11.Provider provider, SecurityObject scope, 
        SessionObject object, aladdin.capi.ansi.x962.IPublicKey publicKey, long flags) throws IOException
    {
        // сохранить переданные параметры
        super(provider, scope, publicKey.keyOID()); 
        
        // получить атрибуты ключа
        keyAttributes = provider.getKeyAttributes(object);
        
        // сохранить параметры открытого ключа
        parameters = (aladdin.capi.ansi.x962.IParameters)publicKey.parameters(); 
        
        // создать атрибут параметров
        Attribute parametersAttribute = PublicKey.getParametersAttribute(parameters, flags); 
        
        // добавить атрибут в список
        keyAttributes = keyAttributes.join(parametersAttribute); 
            
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
        if (keyAttributes.get(API.CKA_VALUE) == null) d = null; 
        else {
            // раскодировать значение параметров
            d = Convert.toBigInteger(
                (byte[])keyAttributes.get(API.CKA_VALUE).value(), ENDIAN
            );
        }
    }
    // параметры ключа
    @Override public final IParameters parameters() { return parameters; }
    
    // секретное значение
	@Override public final BigInteger getS() throws IOException
    { 
        // проверить наличие значения
        if (d != null) return d;

        // при ошибке выбросить исключение
        throw new aladdin.pkcs11.Exception(API.CKR_KEY_UNEXTRACTABLE); 
    }
    // атрибуты ключа
    @Override protected Attributes keyAttributes() { return keyAttributes; } 
}
