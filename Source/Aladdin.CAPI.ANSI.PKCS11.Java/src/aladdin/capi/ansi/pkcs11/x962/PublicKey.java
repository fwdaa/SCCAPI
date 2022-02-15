package aladdin.capi.ansi.pkcs11.x962;
import aladdin.asn1.*; 
import aladdin.capi.*;
import aladdin.capi.pkcs11.*;
import aladdin.pkcs11.*;
import java.security.spec.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Открытый ключ EC/ECDSA
///////////////////////////////////////////////////////////////////////////
public class PublicKey extends aladdin.capi.PublicKey implements aladdin.capi.ansi.x962.IPublicKey
{
    // параметры алгоритма
    private final aladdin.capi.ansi.x962.Parameters parameters; private final ECPoint q; 
    
	// атрибуты параметров
	public static Attribute getParametersAttribute(
         aladdin.capi.ansi.x962.IParameters parameters, long flags)
    {
        // указать фабрику кодирования ключей
        aladdin.capi.ansi.x962.KeyFactory keyFactory = 
            new aladdin.capi.ansi.x962.KeyFactory(aladdin.asn1.ansi.OID.X962_EC_PUBLIC_KEY); 
            
        // при указании идентификатора 
        if (parameters instanceof INamedParameters && (flags & API.CKF_EC_NAMEDCURVE) != 0)
        {
            // закодировать параметры алгоритма
            IEncodable encodedParameters = keyFactory.encodeParameters(
                parameters, aladdin.capi.ec.Encoding.UNCOMPRESSED, true
            ); 
            // вернуть атрибут параметров
            return new Attribute(API.CKA_EC_PARAMS, encodedParameters.encoded()); 
        }
        else if ((flags & API.CKF_EC_COMPRESS) != 0)
        {
            // закодировать параметры алгоритма
            IEncodable encodedParameters = keyFactory.encodeParameters(
                parameters, aladdin.capi.ec.Encoding.COMPRESSED, false
            ); 

            // вернуть атрибут параметров
            return new Attribute(API.CKA_EC_PARAMS, encodedParameters.encoded()); 
        }
        else {
            // закодировать параметры алгоритма
            IEncodable encodedParameters = keyFactory.encodeParameters(
                parameters, aladdin.capi.ec.Encoding.UNCOMPRESSED, false
            ); 
            // вернуть атрибут параметров
            return new Attribute(API.CKA_EC_PARAMS, encodedParameters.encoded()); 
        }
    }
	// атрибуты открытого ключа
	public static Attribute[] getAttributes(
        aladdin.capi.ansi.x962.IPublicKey publicKey, long flags)
    {
        // преобразовать тип параметров
        aladdin.capi.ansi.x962.IParameters parameters = 
            (aladdin.capi.ansi.x962.IParameters)publicKey.parameters(); 
        
        // создать атрибут параметров
        Attribute parametersAttribute = getParametersAttribute(parameters, flags); 
                
        // указать способ кодирования
        aladdin.capi.ec.Encoding encoding = ((flags & API.CKF_EC_COMPRESS) != 0) ? 
            aladdin.capi.ec.Encoding.COMPRESSED : 
            aladdin.capi.ec.Encoding.UNCOMPRESSED; 
        
        // закодировать базовую точку эллиптической кривой
        OctetString encodedPoint = new OctetString(
            parameters.getCurve().encode(publicKey.getW(), encoding)
        );
        // указать атрибут параметров
        Attribute pointAttribute = new Attribute(API.CKA_EC_POINT, encodedPoint.encoded()); 

        // создать набор атрибутов
        return new Attribute[] { new Attribute(API.CKA_KEY_TYPE, API.CKK_EC),

            // указать параметры
            parametersAttribute, pointAttribute
        }; 
    }
    // конструктор
	public PublicKey(aladdin.capi.pkcs11.Provider provider, 
        SessionObject object, long flags) throws IOException 
    {
        // сохранить переданные параметры
        super(provider.getKeyFactory(aladdin.asn1.ansi.OID.X962_EC_PUBLIC_KEY)); 
        
        // указать способ кодирования
        aladdin.capi.ec.Encoding encoding = ((flags & API.CKF_EC_COMPRESS) != 0) ? 
            aladdin.capi.ec.Encoding.COMPRESSED : 
            aladdin.capi.ec.Encoding.UNCOMPRESSED; 
        
        // получить атрибуты ключа
		Attributes keyAttributes = provider.getKeyAttributes(object, 
            new Attribute(API.CKA_EC_PARAMS, byte[].class), 
            new Attribute(API.CKA_EC_POINT , byte[].class) 
        ); 
        // получить закодированное представление параметров
        IEncodable encodedParameters = Encodable.decode(
            (byte[])keyAttributes.get(API.CKA_EC_PARAMS).value()
        ); 
        // раскодировать параметры
        parameters = (aladdin.capi.ansi.x962.Parameters)
            keyFactory().decodeParameters(encodedParameters); 
        
        // получить закодированное представление значения
        OctetString encodedPoint = new OctetString(Encodable.decode(
            (byte[])keyAttributes.get(API.CKA_EC_POINT ).value()
        )); 
        // раскодировать значение
        q = parameters.getCurve().decode(encodedPoint.value(), encoding); 
    }
    // параметры ключа
    @Override public aladdin.capi.ansi.x962.Parameters parameters() { return parameters; }
    // параметры ключа
    @Override public aladdin.capi.ansi.x962.Parameters getParams() { return parameters; }
    
    // точка эллиптической кривой
    @Override public final ECPoint getW() { return q; }
}
