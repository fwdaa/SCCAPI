using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.X957
{
    ///////////////////////////////////////////////////////////////////////////
    // Открытый ключ DH
    ///////////////////////////////////////////////////////////////////////////
    public class PublicKey : CAPI.PublicKey, ANSI.X957.IPublicKey
    {
        // способ кодирования чисел
        private const Math.Endian Endian = Math.Endian.BigEndian; 
    
        // параметры ключа
        private Math.BigInteger p; private Math.BigInteger q;
        private Math.BigInteger g; private Math.BigInteger y;  
    
	    // атрибуты открытого ключа
	    public static CAPI.PKCS11.Attribute[] GetAttributes(
            CAPI.PKCS11.Provider provider, ANSI.X957.IPublicKey publicKey)
        {
            // преобразовать тип параметров
            ANSI.X957.IParameters parameters = (ANSI.X957.IParameters)publicKey.Parameters; 
        
            // закодировать параметры открытого ключа
            byte[] p = Math.Convert.FromBigInteger(parameters.P, Endian); 
            byte[] q = Math.Convert.FromBigInteger(parameters.Q, Endian);
            byte[] g = Math.Convert.FromBigInteger(parameters.G, Endian);        
        
            // закодировать значение ключа
            byte[] y = Math.Convert.FromBigInteger(publicKey.Y, Endian);
        
            // создать набор атрибутов
            return new CAPI.PKCS11.Attribute[] { provider.CreateAttribute(API.CKA_KEY_TYPE, API.CKK_DSA),

                // указать параметры
                provider.CreateAttribute(API.CKA_PRIME,      p), 
                provider.CreateAttribute(API.CKA_SUBPRIME,   q),  
                provider.CreateAttribute(API.CKA_BASE,       g), 
                provider.CreateAttribute(API.CKA_VALUE,      y)  
            }; 
        }
	    // конструктор 
	    public PublicKey(CAPI.PKCS11.Provider provider, CAPI.PKCS11.SessionObject obj)

            // сохранить переданные параметры
            : base(provider.GetKeyFactory(ASN1.ANSI.OID.x957_dsa))
        {
            // получить атрибуты ключа
		    CAPI.PKCS11.Attributes keyAttributes = provider.GetKeyAttributes(obj, 
                new CAPI.PKCS11.Attribute(API.CKA_PRIME   ), 
                new CAPI.PKCS11.Attribute(API.CKA_SUBPRIME), 
                new CAPI.PKCS11.Attribute(API.CKA_BASE    ), 
                new CAPI.PKCS11.Attribute(API.CKA_VALUE   ) 
            ); 
            // раскодировать значение параметров
            p = Math.Convert.ToBigInteger(keyAttributes[API.CKA_PRIME].Value, Endian);

            // раскодировать значение параметров
            q = Math.Convert.ToBigInteger(keyAttributes[API.CKA_SUBPRIME].Value, Endian);

            // раскодировать значение параметров
            g = Math.Convert.ToBigInteger(keyAttributes[API.CKA_BASE].Value, Endian);

            // раскодировать значение параметров
            y = Math.Convert.ToBigInteger(keyAttributes[API.CKA_VALUE].Value, Endian);
        }
        // параметры ключа
        public override IParameters Parameters { get { return new ANSI.X942.Parameters(p, q, g); }}
        // значение ключа
	    public Math.BigInteger Y { get { return y; }}
    }
}
