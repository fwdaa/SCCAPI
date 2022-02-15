using System;
using System.Diagnostics.CodeAnalysis;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.X962
{
    ///////////////////////////////////////////////////////////////////////////
    // Личный ключ EC/ECDSA
    ///////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
    public class PrivateKey : CAPI.PKCS11.PrivateKey, ANSI.X962.IPrivateKey
    {
        // способ кодирования чисел
        private const Math.Endian Endian = Math.Endian.BigEndian; 
    
        // атрибуты ключа и секретное значение
        private CAPI.PKCS11.Attributes keyAttributes; private Math.BigInteger d;  
        // параметры ключа
        private ANSI.X962.IParameters parameters; 
    
	    // атрибуты личного ключа
	    public static CAPI.PKCS11.Attribute[] GetAttributes(
            CAPI.PKCS11.Provider provider, ANSI.X962.IPrivateKey privateKey, ulong flags) 
        {
            // преобразовать тип параметров
            ANSI.X962.IParameters parameters = (ANSI.X962.IParameters)privateKey.Parameters; 
        
            // создать атрибут параметров
            CAPI.PKCS11.Attribute parametersAttribute = 
                PublicKey.GetParametersAttribute(provider, parameters, flags); 
                
            // закодировать значение ключа
            byte[] d = Math.Convert.FromBigInteger(privateKey.D, Endian);
        
            // указать атрибут значения
            CAPI.PKCS11.Attribute valueAttribute = provider.CreateAttribute(API.CKA_VALUE, d); 
        
            // создать набор атрибутов
            return new CAPI.PKCS11.Attribute[] { 

                // указать тип ключа
                provider.CreateAttribute(API.CKA_KEY_TYPE, API.CKK_EC),

                // указать параметры
                parametersAttribute, valueAttribute
            }; 
        }
	    // конструктор 
	    public PrivateKey(CAPI.PKCS11.Provider provider, SecurityObject scope, 
            CAPI.PKCS11.SessionObject obj, ANSI.X962.IPublicKey publicKey, 
            ulong flags) : base(provider, scope, publicKey.KeyOID)
        {
            // получить атрибуты ключа
            keyAttributes = provider.GetKeyAttributes(obj);
        
            // сохранить параметры открытого ключа
            parameters = (ANSI.X962.IParameters)publicKey.Parameters; 
        
            // создать атрибут параметров
            CAPI.PKCS11.Attribute parametersAttribute = 
                PublicKey.GetParametersAttribute(provider, parameters, flags); 
        
            // добавить атрибут в список
            keyAttributes = keyAttributes.Join(parametersAttribute); 
            
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
                if (keyAttributes[API.CKA_VALUE] == null)
                {
                    // при ошибке выбросить исключение
                    throw new Aladdin.PKCS11.Exception(API.CKR_KEY_UNEXTRACTABLE); 
                }
            }
            // проверить наличие атрибута
            if (keyAttributes[API.CKA_VALUE] == null) d = null; 
            else {
                // раскодировать значение параметров
                d = Math.Convert.ToBigInteger(keyAttributes[API.CKA_VALUE].Value, Endian);
            }
        }
        // параметры ключа
        public override IParameters Parameters { get { return parameters; }}
    
        // секретное значение
        [SuppressMessage("Microsoft.Design", "CA1065:DoNotRaiseExceptionsInUnexpectedLocations")]
	    public Math.BigInteger D { get 
        { 
            // проверить наличие значения
            if (d != null) return d;

            // при ошибке выбросить исключение
            throw new Aladdin.PKCS11.Exception(API.CKR_KEY_UNEXTRACTABLE); 
        }}
        // атрибуты ключа
        protected override CAPI.PKCS11.Attributes KeyAttributes { get { return keyAttributes; }}
    }
}
