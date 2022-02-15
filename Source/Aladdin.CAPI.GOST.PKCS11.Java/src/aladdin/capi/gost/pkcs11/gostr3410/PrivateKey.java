package aladdin.capi.gost.pkcs11.gostr3410;
import aladdin.math.*; 
import aladdin.asn1.*;
import aladdin.capi.*; 
import aladdin.capi.pkcs11.*; 
import aladdin.pkcs11.*;
import java.math.*; 
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Личный ключ ГОСТ R 34.10-2001
///////////////////////////////////////////////////////////////////////////
public class PrivateKey extends aladdin.capi.pkcs11.PrivateKey 
    implements aladdin.capi.gost.gostr3410.IECPrivateKey
{
    // способ кодирования чисел
    private static final Endian ENDIAN = Endian.LITTLE_ENDIAN; 
    
    // атрибуты ключа и секретное значение
    private Attributes keyAttributes; private final BigInteger d;
    // параметры ключа
    private final aladdin.capi.gost.gostr3410.ECNamedParameters2001 parameters; 
    
	// атрибуты личного ключа
	public static Attribute[] getAttributes(
        aladdin.capi.gost.gostr3410.IECPrivateKey privateKey) throws IOException
    {
        // преобразовать тип параметров
        aladdin.capi.gost.gostr3410.INamedParameters parameters = 
            (aladdin.capi.gost.gostr3410.INamedParameters)privateKey.parameters(); 

        // закодировать значения идентификаторов
        byte[] encodedParamOID = new ObjectIdentifier(parameters.paramOID()).encoded(); 
        byte[] encodedHashOID  = new ObjectIdentifier(parameters.hashOID ()).encoded(); 
        byte[] encodedSBoxOID  = new ObjectIdentifier(parameters.sboxOID ()).encoded(); 

        // закодировать секретное значение
        byte[] encodedD = Convert.fromBigInteger(privateKey.getS(), ENDIAN); 

        // определить размер личного ключа в байтах
        int cb = (((aladdin.capi.gost.gostr3410.IECParameters)parameters).getOrder().bitLength() + 7) / 8; 

        // определить идентификатор алгоритма
        long keyType = (cb == 32) ? API.CKK_GOSTR3410 : API.CKK_GOSTR3410_512; 
        
        // выделить память для кодирования значения
        byte[] encodedValue = new byte[cb]; 

        // скопировать секретное значение
        System.arraycopy(encodedD, 0, encodedValue,  0, encodedD.length); 

        // для 256-битного ключа
        if (keyType == API.CKK_GOSTR3410)
        {
            // создать набор атрибутов
            return new Attribute[] { new Attribute(API.CKA_KEY_TYPE, keyType),

                // указать идентификаторы параметров
                new Attribute(API.CKA_GOSTR3410_PARAMS, encodedParamOID), 
                new Attribute(API.CKA_GOSTR3411_PARAMS, encodedHashOID ), 
                new Attribute(API.CKA_GOST28147_PARAMS, encodedSBoxOID ), 

                // указать значение ключа
                new Attribute(API.CKA_VALUE, encodedValue)
            }; 
        }
        else {
            // создать набор атрибутов
            return new Attribute[] { new Attribute(API.CKA_KEY_TYPE, keyType),

                // указать идентификаторы параметров
                new Attribute(API.CKA_GOSTR3410_PARAMS, encodedParamOID), 

                // указать значение ключа
                new Attribute(API.CKA_VALUE, encodedValue)
            }; 
        }
    }
	// конструктор 
	public PrivateKey(aladdin.capi.pkcs11.Provider provider, SecurityObject scope, 
        SessionObject obj, IPublicKey publicKey) throws IOException
    {
        // сохранить переданные параметры
        super(provider, scope, publicKey.keyOID()); keyAttributes = provider.getKeyAttributes(obj); 
        
        // сохранить параметры открытого ключа
        parameters = (aladdin.capi.gost.gostr3410.ECNamedParameters2001)publicKey.parameters(); 
        
        if (publicKey.keyOID().equals(aladdin.asn1.gost.OID.GOSTR3410_2012_512))
        {
            // закодировать параметры открытого ключа
            byte[] encodedParamOID = new ObjectIdentifier(parameters.paramOID()).encoded(); 

            // указать атрибуты открытого ключа
            Attributes publicAttributes = new Attributes(
                new Attribute(API.CKA_GOSTR3410_PARAMS, encodedParamOID)
            ); 
            // добавить атрибуты в список
            keyAttributes = keyAttributes.join(publicAttributes); 
        }
        else {
            // закодировать параметры открытого ключа
            byte[] encodedParamOID = new ObjectIdentifier(parameters.paramOID()).encoded(); 
            byte[] encodedHashOID  = new ObjectIdentifier(parameters.hashOID ()).encoded(); 

            // указать атрибуты открытого ключа
            Attributes publicAttributes = new Attributes(
                new Attribute(API.CKA_GOSTR3410_PARAMS, encodedParamOID), 
                new Attribute(API.CKA_GOSTR3411_PARAMS, encodedHashOID )
            ); 
            // при указании идентификатора таблицы подстановок
            if (parameters.sboxOID() != null)
            {
                // закодировать идентификатор таблицы подстановок
                byte[] encodedSBoxOID = new ObjectIdentifier(parameters.sboxOID()).encoded(); 

                // получить значение ключа
                Attribute attribute = new Attribute(API.CKA_GOST28147_PARAMS, encodedSBoxOID); 

                // добавить атрибут в список
                publicAttributes = publicAttributes.join(attribute); 
            }
            // добавить атрибуты в список
            keyAttributes = keyAttributes.join(publicAttributes); 
        }
        // при возможности извлечения значения
        if ((Byte)keyAttributes.get(API.CKA_EXTRACTABLE).value() != API.CK_FALSE && 
            (Byte)keyAttributes.get(API.CKA_SENSITIVE  ).value() == API.CK_FALSE)
        {
            // получить значение ключа
            Attribute attribute = new Attribute(API.CKA_VALUE, obj.getValue()); 
          
            // добавить атрибут в список
            keyAttributes = keyAttributes.join(attribute); 
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
        // при отсутствии значения атрибута
        if (keyAttributes.get(API.CKA_VALUE) == null) d = null; 
        else {
            // получить закодированные значения идентификаторов
            byte[] encodedValue = (byte[])keyAttributes.get(API.CKA_VALUE).value();

            // раскодировать секретное значение
            d = Convert.toBigInteger(encodedValue, ENDIAN); 
        }
    }
    // параметры ключа
    @Override public IParameters parameters() { return parameters; }
    
	// секретное значение
    @Override public BigInteger getS() throws IOException
    { 
        // проверить наличие значения
        if (d != null) return d; 
        
        // при ошибке выбросить исключение
        throw new aladdin.pkcs11.Exception(API.CKR_KEY_UNEXTRACTABLE); 
	}
    // атрибуты ключа
    @Override protected Attributes keyAttributes() { return keyAttributes; } 
}
