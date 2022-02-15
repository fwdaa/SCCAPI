using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.X962
{
    ///////////////////////////////////////////////////////////////////////////
    // Открытый ключ EC/ECDSA
    ///////////////////////////////////////////////////////////////////////////
    public class PublicKey : CAPI.PublicKey, ANSI.X962.IPublicKey
    {
        // параметры алгоритма
        private ANSI.X962.IParameters parameters; private EC.Point q; 
    
	    // атрибуты параметров
	    public static CAPI.PKCS11.Attribute GetParametersAttribute(
            CAPI.PKCS11.Provider provider, ANSI.X962.IParameters parameters, ulong flags)
        {
            // указать фабрику кодирования ключей
            ANSI.X962.KeyFactory keyFactory = new ANSI.X962.KeyFactory(
                ASN1.ANSI.OID.x962_ec_public_key
            ); 
            // при указании идентификатора 
            if (parameters is INamedParameters && (flags & API.CKF_EC_NAMEDCURVE) != 0)
            {
                // закодировать параметры алгоритма
                ASN1.IEncodable encodedParameters = keyFactory.EncodeParameters(
                    parameters, EC.Encoding.Uncompressed, true
                ); 
                // вернуть атрибут параметров
                return provider.CreateAttribute(API.CKA_EC_PARAMS, encodedParameters.Encoded); 
            }
            else if ((flags & API.CKF_EC_COMPRESS) != 0)
            {
                // закодировать параметры алгоритма
                ASN1.IEncodable encodedParameters = keyFactory.EncodeParameters(
                    parameters, EC.Encoding.Compressed, false
                ); 
                // вернуть атрибут параметров
                return provider.CreateAttribute(API.CKA_EC_PARAMS, encodedParameters.Encoded); 
            }
            else {
                // закодировать параметры алгоритма
                ASN1.IEncodable encodedParameters = keyFactory.EncodeParameters(
                    parameters, EC.Encoding.Uncompressed, false
                ); 
                // вернуть атрибут параметров
                return provider.CreateAttribute(API.CKA_EC_PARAMS, encodedParameters.Encoded); 
            }
        }
	    // атрибуты открытого ключа
	    public static CAPI.PKCS11.Attribute[] GetAttributes(
            CAPI.PKCS11.Provider provider, ANSI.X962.IPublicKey publicKey, ulong flags)
        {
            // преобразовать тип параметров
            ANSI.X962.IParameters parameters = (ANSI.X962.IParameters)publicKey.Parameters; 
        
            // создать атрибут параметров
            CAPI.PKCS11.Attribute parametersAttribute = GetParametersAttribute(
                provider, parameters, flags
            ); 
            // указать способ кодирования
            EC.Encoding encoding = ((flags & API.CKF_EC_COMPRESS) != 0) ? 
                 EC.Encoding.Compressed : EC.Encoding.Uncompressed; 
        
            // закодировать базовую точку эллиптической кривой
            ASN1.OctetString encodedPoint = new ASN1.OctetString(
                parameters.Curve.Encode(publicKey.Q, encoding)
            );
            // указать атрибут параметров
            CAPI.PKCS11.Attribute pointAttribute = provider.CreateAttribute(
                API.CKA_EC_POINT, encodedPoint.Encoded
            ); 
            // создать набор атрибутов
            return new CAPI.PKCS11.Attribute[] { provider.CreateAttribute(API.CKA_KEY_TYPE, API.CKK_EC),

                // указать параметры
                parametersAttribute, pointAttribute
            }; 
        }
        // конструктор
	    public PublicKey(CAPI.PKCS11.Provider provider, CAPI.PKCS11.SessionObject obj, ulong flags) 

            // сохранить переданные параметры
            : base(provider.GetKeyFactory(ASN1.ANSI.OID.x962_ec_public_key))
        {
            // указать способ кодирования
            EC.Encoding encoding = ((flags & API.CKF_EC_COMPRESS) != 0) ? 
                 EC.Encoding.Compressed : EC.Encoding.Uncompressed; 

            // получить атрибуты ключа
		    CAPI.PKCS11.Attributes keyAttributes = provider.GetKeyAttributes(obj, 
                new CAPI.PKCS11.Attribute(API.CKA_EC_PARAMS), 
                new CAPI.PKCS11.Attribute(API.CKA_EC_POINT ) 
            ); 
            // получить закодированное представление параметров
            ASN1.IEncodable encodedParameters = ASN1.Encodable.Decode(
                keyAttributes[API.CKA_EC_PARAMS].Value
            ); 
            // раскодировать параметры
            parameters = (ANSI.X962.IParameters)
                KeyFactory.DecodeParameters(encodedParameters); 
        
            // получить закодированное представление значения
            ASN1.OctetString encodedPoint = new ASN1.OctetString(
                ASN1.Encodable.Decode(keyAttributes[API.CKA_EC_POINT].Value)
            ); 
            // раскодировать значение
            q = parameters.Curve.Decode(encodedPoint.Value, encoding); 
        }
        // параметры ключа
        public override IParameters Parameters { get { return parameters; }}

        // точка эллиптической кривой
        public EC.Point Q { get { return q; }}
    }
}
