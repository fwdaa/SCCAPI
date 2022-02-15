using System;
using System.Diagnostics.CodeAnalysis;
using Aladdin.PKCS11;

namespace Aladdin.CAPI.GOST.PKCS11.GOSTR3410
{
	///////////////////////////////////////////////////////////////////////////
	// Личный ключ ГОСТ R 34.10-2001
	///////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
	public class PrivateKey : CAPI.PKCS11.PrivateKey, CAPI.GOST.GOSTR3410.IECPrivateKey
	{
        // указать способ кодирования чисел
        private const Math.Endian Endian = Math.Endian.LittleEndian; 

        // атрибуты ключа и секретное значение
        private CAPI.PKCS11.Attributes keyAttributes; private Math.BigInteger d;
        // параметры ключа
        private GOST.GOSTR3410.INamedParameters parameters; 

		// получить атрибуты открытого ключа
		public static CAPI.PKCS11.Attribute[] GetAttributes(
            CAPI.PKCS11.Provider provider, GOST.GOSTR3410.IECPrivateKey privateKey)
        {
	        // преобразовать тип параметров
	        GOST.GOSTR3410.INamedParameters parameters = 
		        (GOST.GOSTR3410.INamedParameters)privateKey.Parameters; 

	        // закодировать значения идентификаторов
	        byte[] encodedParamOID = new ASN1.ObjectIdentifier(parameters.ParamOID).Encoded; 
	        byte[] encodedHashOID  = new ASN1.ObjectIdentifier(parameters.HashOID ).Encoded; 
	        byte[] encodedSBoxOID  = new ASN1.ObjectIdentifier(parameters.SBoxOID ).Encoded; 

	        // закодировать секретное значение
	        byte[] encodedD = Math.Convert.FromBigInteger(privateKey.D, Endian); 

            // определить размер личного ключа в байтах
            int cb = (((GOST.GOSTR3410.IECParameters)parameters).Order.BitLength + 7) / 8; 

	        // определить идентификатор алгоритма
	        ulong keyType = (cb == 32) ? API.CKK_GOSTR3410 : API.CKK_GOSTR3410_512; 

	        // выделить память для кодирования значения
	        byte[] encodedValue = new byte[cb]; 

	        // скопировать секретное значение
	        Array.Copy(encodedD, 0, encodedValue,  0, encodedD.Length); 

	        // для 256-битного ключа
	        if (keyType == API.CKK_GOSTR3410)
	        {
		        // создать набор атрибутов
		        return new CAPI.PKCS11.Attribute[] { provider.CreateAttribute(API.CKA_KEY_TYPE, keyType),

			        // указать идентификаторы параметров
			        provider.CreateAttribute(API.CKA_GOSTR3410_PARAMS, encodedParamOID), 
			        provider.CreateAttribute(API.CKA_GOSTR3411_PARAMS, encodedHashOID ), 
			        provider.CreateAttribute(API.CKA_GOST28147_PARAMS, encodedSBoxOID ), 

			        // указать значение ключа
			        provider.CreateAttribute(API.CKA_VALUE, encodedValue)
		        }; 
	        }
	        else {
		        // создать набор атрибутов
		        return new CAPI.PKCS11.Attribute[] { provider.CreateAttribute(API.CKA_KEY_TYPE, keyType),

			        // указать идентификаторы параметров
			        provider.CreateAttribute(API.CKA_GOSTR3410_PARAMS, encodedParamOID), 

			        // указать значение ключа
			        provider.CreateAttribute(API.CKA_VALUE, encodedValue)
		        }; 
	        }
        }
		// преобразовать тип ключа
		public PrivateKey(CAPI.PKCS11.Provider provider, SecurityObject scope, 
            CAPI.PKCS11.SessionObject obj, IPublicKey publicKey) 
            : base(provider, scope, publicKey.KeyOID)
        {
	        // получить атрибуты ключа
	        keyAttributes = provider.GetKeyAttributes(obj); 
        
            // сохранить параметры открытого ключа
	        parameters = (GOST.GOSTR3410.INamedParameters)publicKey.Parameters; 

            if (publicKey.KeyOID == ASN1.GOST.OID.gostR3410_2012_512)
            {
                // закодировать параметры открытого ключа
                byte[] encodedParamOID = new ASN1.ObjectIdentifier(parameters.ParamOID).Encoded; 

                // указать атрибуты открытого ключа
                CAPI.PKCS11.Attributes publicAttributes = new CAPI.PKCS11.Attributes(
                    provider.CreateAttribute(API.CKA_GOSTR3410_PARAMS, encodedParamOID)  
                ); 
                // добавить атрибуты в список
                keyAttributes = keyAttributes.Join(publicAttributes); 
            }
	        else {
                // закодировать параметры открытого ключа
                byte[] encodedParamOID = new ASN1.ObjectIdentifier(parameters.ParamOID).Encoded; 
                byte[] encodedHashOID  = new ASN1.ObjectIdentifier(parameters.HashOID ).Encoded; 

                // указать атрибуты открытого ключа
                CAPI.PKCS11.Attributes publicAttributes = new CAPI.PKCS11.Attributes(
                    provider.CreateAttribute(API.CKA_GOSTR3410_PARAMS, encodedParamOID), 
                    provider.CreateAttribute(API.CKA_GOSTR3411_PARAMS, encodedHashOID )
                ); 
                // при указании идентификатора таблицы подстановок
                if (parameters.SBoxOID != null)
                {
                    // закодировать идентификатор таблицы подстановок
                    byte[] encodedSBoxOID  = new ASN1.ObjectIdentifier(parameters.SBoxOID).Encoded; 

                    // получить значение ключа
                    CAPI.PKCS11.Attribute attribute = 
                        provider.CreateAttribute(API.CKA_GOST28147_PARAMS, encodedSBoxOID);

                    // добавить атрибут в список
                    publicAttributes = publicAttributes.Join(attribute); 
                }
                // добавить атрибуты в список
                keyAttributes = keyAttributes.Join(publicAttributes); 
            }
            // при возможности извлечения значения
            if (keyAttributes[API.CKA_EXTRACTABLE].GetByte() != API.CK_FALSE && 
                keyAttributes[API.CKA_SENSITIVE  ].GetByte() == API.CK_FALSE)
            {
                // получить значение ключа
                CAPI.PKCS11.Attribute attribute = 
                    provider.CreateAttribute(API.CKA_VALUE, obj.GetValue()); 
            
                // добавить атрибут в список
                keyAttributes = keyAttributes.Join(attribute); 
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
            // проверить наличие значения
            if (keyAttributes[API.CKA_VALUE] == null) d = null;
            else { 
	            // получить закодированные значения идентификаторов
	            byte[] encodedValue = keyAttributes[API.CKA_VALUE].Value;

		        // раскодировать секретное значение
		        d = Math.Convert.ToBigInteger(encodedValue, Endian); 
	        }
        }
        // параметры ключа
        public override IParameters Parameters { get { return parameters; }}

		// секретное значение
        [SuppressMessage("Microsoft.Design", "CA1065:DoNotRaiseExceptionsInUnexpectedLocations")]
        public virtual Math.BigInteger D { get { if (d != null) return d; 
            
            // при ошибке выбросить исключение
            throw new Aladdin.PKCS11.Exception(API.CKR_KEY_UNEXTRACTABLE);
        }}
        // атрибуты ключа
        protected override CAPI.PKCS11.Attributes KeyAttributes { get { return keyAttributes; }}
	}
}
