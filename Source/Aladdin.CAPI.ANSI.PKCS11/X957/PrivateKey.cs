using System;
using System.Diagnostics.CodeAnalysis;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.X957
{
    ///////////////////////////////////////////////////////////////////////////
    // Личный ключ DH
    ///////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
    public class PrivateKey : CAPI.PKCS11.PrivateKey, ANSI.X957.IPrivateKey
    {
        // способ кодирования чисел
        private const Math.Endian Endian = Math.Endian.BigEndian; 
    
        // атрибуты ключа и секретное значение
        private CAPI.PKCS11.Attributes keyAttributes; private Math.BigInteger x;  
        // параметры ключа
        private ANSI.X957.IParameters parameters; 
    
	    // атрибуты личного ключа
	    public static CAPI.PKCS11.Attribute[] GetAttributes(
            CAPI.PKCS11.Provider provider, ANSI.X957.IPrivateKey privateKey)
        {
            // преобразовать тип параметров
            ANSI.X957.IParameters parameters = (ANSI.X957.IParameters)privateKey.Parameters; 
        
            // закодировать параметры личного ключа
            byte[] p = Math.Convert.FromBigInteger(parameters.P, Endian); 
            byte[] q = Math.Convert.FromBigInteger(parameters.Q, Endian);
            byte[] g = Math.Convert.FromBigInteger(parameters.G, Endian);        
        
            // закодировать значение ключа
            byte[] x = Math.Convert.FromBigInteger(privateKey.X, Endian);
        
            // создать набор атрибутов
            return new CAPI.PKCS11.Attribute[] { provider.CreateAttribute(API.CKA_KEY_TYPE, API.CKK_DSA),

                // указать параметры
                provider.CreateAttribute(API.CKA_PRIME,      p), 
                provider.CreateAttribute(API.CKA_SUBPRIME,   q),  
                provider.CreateAttribute(API.CKA_BASE ,      g), 
                provider.CreateAttribute(API.CKA_VALUE,      x)  
            }; 
        }
	    // конструктор 
	    public PrivateKey(CAPI.PKCS11.Provider provider, SecurityObject scope, 
            CAPI.PKCS11.SessionObject obj, ANSI.X957.IPublicKey publicKey) 
            : base(provider, scope, publicKey.KeyOID)
        {
            // получить атрибуты объекта
            keyAttributes = provider.GetKeyAttributes(obj); 

            // сохранить параметры открытого ключа
            parameters = (ANSI.X957.IParameters)publicKey.Parameters; 
        
            // закодировать параметры личного ключа
            byte[] p = Math.Convert.FromBigInteger(parameters.P, Endian); 
            byte[] q = Math.Convert.FromBigInteger(parameters.Q, Endian);
            byte[] g = Math.Convert.FromBigInteger(parameters.G, Endian);        
        
            // указать атрибуты открытого ключа
            CAPI.PKCS11.Attribute[] publicAttributes = new CAPI.PKCS11.Attribute[] {
                provider.CreateAttribute(API.CKA_PRIME   , p), 
                provider.CreateAttribute(API.CKA_SUBPRIME, q), 
                provider.CreateAttribute(API.CKA_BASE    , g) 
            }; 
            // добавить атрибуты в список
            keyAttributes = keyAttributes.Join(publicAttributes); 
            
            // при возможности извлечения значения
            if (keyAttributes[API.CKA_EXTRACTABLE].GetByte() != API.CK_FALSE && 
                keyAttributes[API.CKA_SENSITIVE  ].GetByte() == API.CK_FALSE)
            {
                // указать требуемые атрибуты
                CAPI.PKCS11.Attribute[] attributes = new CAPI.PKCS11.Attribute[] {
                    new CAPI.PKCS11.Attribute(API.CKA_VALUE) 
                }; 
                // получить атрибуты ключа
                attributes = obj.GetAttributes(attributes); 
            
                // добавить атрибут в список
                keyAttributes = keyAttributes.Join(attributes); 
            }
            // при отсутствии на смарт-карте
            if (keyAttributes[API.CKA_TOKEN].GetByte() == API.CK_FALSE)
            {
                // проверить наличие значения
                if (keyAttributes[API.CKA_PRIVATE_EXPONENT] == null)
                {
                    // при ошибке выбросить исключение
                    throw new Aladdin.PKCS11.Exception(API.CKR_KEY_UNEXTRACTABLE); 
                }
            }
            // проверить наличие атрибута
            if (keyAttributes[API.CKA_VALUE] == null) x = null; 
            else {
                // раскодировать значение параметров
                x = Math.Convert.ToBigInteger(
                    keyAttributes[API.CKA_VALUE].Value, Endian
                );
            }
        }
        public override CAPI.IParameters Parameters { get { return parameters; }}
    
        [SuppressMessage("Microsoft.Design", "CA1065:DoNotRaiseExceptionsInUnexpectedLocations")]
	    public Math.BigInteger X { get  
        { 
            // проверить наличие значения
            if (x != null) return x;

            // при ошибке выбросить исключение
            throw new Aladdin.PKCS11.Exception(API.CKR_KEY_UNEXTRACTABLE); 
        }}
        // атрибуты ключа
        protected override CAPI.PKCS11.Attributes KeyAttributes { get { return keyAttributes; }}
    }
}
