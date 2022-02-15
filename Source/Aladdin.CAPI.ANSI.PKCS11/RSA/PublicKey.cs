using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.RSA
{
    ///////////////////////////////////////////////////////////////////////////
    // Открытый ключ RSA
    ///////////////////////////////////////////////////////////////////////////
    public class PublicKey : CAPI.PublicKey, CAPI.ANSI.RSA.IPublicKey
    {
        // способ кодирования чисел
        private const Math.Endian Endian = Math.Endian.BigEndian; 
    
	    private Math.BigInteger modulus;        // параметр N
	    private Math.BigInteger publicExponent;	// параметр E
    
	    // атрибуты открытого ключа
	    public static CAPI.PKCS11.Attribute[] GetAttributes(
            CAPI.PKCS11.Provider provider, CAPI.ANSI.RSA.IPublicKey publicKey)
        {
            // закодировать параметры открытого ключа
            byte[] modulus        = Math.Convert.FromBigInteger(publicKey.Modulus       , Endian); 
            byte[] publicExponent = Math.Convert.FromBigInteger(publicKey.PublicExponent, Endian);
        
            // создать набор атрибутов
            return new CAPI.PKCS11.Attribute[] { provider.CreateAttribute(API.CKA_KEY_TYPE, API.CKK_RSA),

                // указать идентификаторы параметров
                provider.CreateAttribute(API.CKA_MODULUS        , modulus       ),
                provider.CreateAttribute(API.CKA_PUBLIC_EXPONENT, publicExponent) 
            }; 
        }
        // конструктор
	    public PublicKey(CAPI.PKCS11.Provider provider, CAPI.PKCS11.SessionObject obj)

            // сохранить переданные параметры
            : base(provider.GetKeyFactory(ASN1.ISO.PKCS.PKCS1.OID.rsa))
        {
		    // получить атрибуты ключа
		    CAPI.PKCS11.Attributes keyAttributes = provider.GetKeyAttributes(obj, 
                new CAPI.PKCS11.Attribute(API.CKA_MODULUS        ), 
                new CAPI.PKCS11.Attribute(API.CKA_PUBLIC_EXPONENT) 
            ); 
            // раскодировать значение параметров
            modulus = Math.Convert.ToBigInteger(
                keyAttributes[API.CKA_MODULUS].Value, Endian
            );
            publicExponent = Math.Convert.ToBigInteger(
                keyAttributes[API.CKA_PUBLIC_EXPONENT].Value, Endian
            );
        }
        // параметры ключа
        public override IParameters Parameters
        {
            // параметры ключа
            get { return new ANSI.RSA.Parameters(modulus.BitLength, publicExponent); }     
        }
	    public Math.BigInteger Modulus        { get { return modulus;        }}
	    public Math.BigInteger PublicExponent { get { return publicExponent; }}
    }
}
