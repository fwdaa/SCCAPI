package aladdin.capi.gost.pkcs11.gostr3410;
import aladdin.math.*; 
import aladdin.asn1.*;
import aladdin.capi.pkcs11.*; 
import aladdin.pkcs11.*;
import java.security.spec.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Открытый ключ ГОСТ R 34.10-2001
///////////////////////////////////////////////////////////////////////////
public class PublicKey extends aladdin.capi.PublicKey implements aladdin.capi.gost.gostr3410.IECPublicKey
{
    // способ кодирования чисел
    private static final Endian ENDIAN = Endian.LITTLE_ENDIAN; 
    
    // параметры ключа
    private final aladdin.capi.gost.gostr3410.ECNamedParameters parameters; 
    // координаты X и Y точки
    private final ECPoint q;
    
	// атрибуты открытого ключа
	public static Attribute[] getAttributes(aladdin.capi.gost.gostr3410.IECPublicKey publicKey)
    {
        // преобразовать тип параметров
        aladdin.capi.gost.gostr3410.INamedParameters parameters = 
            (aladdin.capi.gost.gostr3410.INamedParameters)publicKey.parameters(); 

        // закодировать значения идентификаторов
        byte[] encodedParamOID = new ObjectIdentifier(parameters.paramOID()).encoded(); 
        byte[] encodedHashOID  = new ObjectIdentifier(parameters.hashOID ()).encoded(); 
        byte[] encodedSBoxOID  = new ObjectIdentifier(parameters.sboxOID ()).encoded(); 

        // закодировать координаты точки
        byte[] encodedQX = Convert.fromBigInteger(publicKey.getW().getAffineX(), ENDIAN); 
        byte[] encodedQY = Convert.fromBigInteger(publicKey.getW().getAffineY(), ENDIAN);

        // определить размер личного ключа в байтах
        int cb = (((aladdin.capi.gost.gostr3410.IECParameters)parameters).getOrder().bitLength() + 7) / 8; 

        // определить идентификатор алгоритма
        long keyType = (cb == 32) ? API.CKK_GOSTR3410 : API.CKK_GOSTR3410_512; 
        
        // выделить память для кодирования значения
        byte[] encodedValue = new byte[cb * 2]; 

        // скопировать координаты точки
        System.arraycopy(encodedQX, 0, encodedValue,  0, encodedQX.length); 
        System.arraycopy(encodedQY, 0, encodedValue, cb, encodedQY.length); 
        
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
	public PublicKey(Provider provider, SessionObject object, String keyOID) throws IOException
    {
        // сохранить переданные параметры
        super(provider.getKeyFactory(keyOID)); Attributes keyAttributes = null; 
        
        // в зависимости от идентификатора ключа
        if (keyOID.equals(aladdin.asn1.gost.OID.GOSTR3410_2012_512))
        {
		    // получить атрибуты ключа
		    keyAttributes = provider.getKeyAttributes(object, 
                new Attribute(API.CKA_GOSTR3410_PARAMS, byte[].class), 
                new Attribute(API.CKA_VALUE,            byte[].class) 
            ); 
            // определить параметры ключа
            ObjectIdentifier paramOID = new ObjectIdentifier(Encodable.decode(
                (byte[])keyAttributes.get(API.CKA_GOSTR3410_PARAMS).value()
            )); 
            // указать фиксированные параметры ключа
            String hashOID = aladdin.asn1.gost.OID.GOSTR3411_2012_512; 

            // создать параметры
            parameters = new aladdin.capi.gost.gostr3410.ECNamedParameters2012(
                paramOID.value(), hashOID
            );
        }
        // в зависимости от идентификатора ключа
        else if (keyOID.equals(aladdin.asn1.gost.OID.GOSTR3410_2012_256))
        {
		    // получить атрибуты ключа
		    keyAttributes = provider.getKeyAttributes(object, 
                new Attribute(API.CKA_GOSTR3410_PARAMS, byte[].class), 
                new Attribute(API.CKA_GOSTR3411_PARAMS, 
                    new ObjectIdentifier(aladdin.asn1.gost.OID.GOSTR3411_2012_256).encoded()), 
                new Attribute(API.CKA_VALUE, byte[].class) 
            ); 
            // определить параметры ключа
            ObjectIdentifier paramOID = new ObjectIdentifier(Encodable.decode(
                (byte[])keyAttributes.get(API.CKA_GOSTR3410_PARAMS).value()
            )); 
            // определить параметры ключа
            ObjectIdentifier hashOID  = new ObjectIdentifier(Encodable.decode(
                (byte[])keyAttributes.get(API.CKA_GOSTR3411_PARAMS).value())
            ); 
            // создать параметры
            parameters = new aladdin.capi.gost.gostr3410.ECNamedParameters2012(
                paramOID.value(), hashOID.value()
            );
        }
        // в зависимости от идентификатора ключа
        else if (keyOID.equals(aladdin.asn1.gost.OID.GOSTR3410_2001))
        {
		    // получить атрибуты ключа
		    keyAttributes = provider.getKeyAttributes(object, 
                new Attribute(API.CKA_GOSTR3410_PARAMS, byte[].class), 
                new Attribute(API.CKA_GOSTR3411_PARAMS, 
                    new ObjectIdentifier(aladdin.asn1.gost.OID.HASHES_CRYPTOPRO).encoded()), 
                new Attribute(API.CKA_GOST28147_PARAMS, 
                    new ObjectIdentifier(aladdin.asn1.gost.OID.ENCRYPTS_A      ).encoded()), 
                new Attribute(API.CKA_VALUE, byte[].class) 
            ); 
            // определить параметры ключа
            ObjectIdentifier paramOID = new ObjectIdentifier(Encodable.decode(
                (byte[])keyAttributes.get(API.CKA_GOSTR3410_PARAMS).value()
            )); 
            // определить параметры ключа
            ObjectIdentifier hashOID  = new ObjectIdentifier(Encodable.decode(
                (byte[])keyAttributes.get(API.CKA_GOSTR3411_PARAMS).value())
            ); 
            // определить параметры ключа
            ObjectIdentifier sboxOID  = new ObjectIdentifier(Encodable.decode(
                (byte[])keyAttributes.get(API.CKA_GOST28147_PARAMS).value()
            )); 
            // создать параметры
            parameters = new aladdin.capi.gost.gostr3410.ECNamedParameters2001(
                paramOID.value(), hashOID.value(), sboxOID.value()
            );
        }
        // при ошибке выбросить исключение
        else throw new aladdin.pkcs11.Exception(API.CKR_KEY_TYPE_INCONSISTENT); 
        
        // получить закодированные значения идентификаторов и ключа
        byte[] encodedValue = (byte[])keyAttributes.get(API.CKA_VALUE).value();
        
        // определить размер значения и указать способ кодирования чисел
        int cb = encodedValue.length; byte[] qx = new byte[cb / 2]; byte[] qy = new byte[cb / 2]; 
        
        // извлечь координаты точки
        System.arraycopy(encodedValue,      0, qx, 0, cb / 2);  
        System.arraycopy(encodedValue, cb / 2, qy, 0, cb / 2); 

        // раскодировать координаты точки
        q = new ECPoint(Convert.toBigInteger(qx, ENDIAN), Convert.toBigInteger(qy, ENDIAN)); 
    }
    // параметры ключа
    @Override public aladdin.capi.gost.gostr3410.ECParameters parameters() { return parameters; }
    // параметры ключа
    @Override public aladdin.capi.gost.gostr3410.ECParameters getParams() { return parameters; }
	// координаты X и Y точки
    @Override public ECPoint getW() { return q; }	
};
