using System;
using Aladdin.PKCS11;

namespace Aladdin.CAPI.GOST.PKCS11.GOSTR3410
{
	///////////////////////////////////////////////////////////////////////////
	// Открытый ключ ГОСТ R 34.10-2001
	///////////////////////////////////////////////////////////////////////////
	public class PublicKey : CAPI.PublicKey, CAPI.GOST.GOSTR3410.IECPublicKey
	{
        // указать способ кодирования чисел
        private const Math.Endian Endian = Math.Endian.LittleEndian; 

        // параметры ключа и координаты X и Y точки
        private GOST.GOSTR3410.ECNamedParameters parameters; private EC.Point q;

		// получить атрибуты открытого ключа
		public static CAPI.PKCS11.Attribute[] GetAttributes(
            CAPI.PKCS11.Provider provider, GOST.GOSTR3410.IECPublicKey publicKey)
        {
	        // преобразовать тип параметров
	        GOST.GOSTR3410.INamedParameters parameters = 
		        (GOST.GOSTR3410.INamedParameters)publicKey.Parameters; 

	        // закодировать значения идентификаторов
	        byte[] encodedParamOID = new ASN1.ObjectIdentifier(parameters.ParamOID).Encoded; 
	        byte[] encodedHashOID  = new ASN1.ObjectIdentifier(parameters.HashOID ).Encoded; 
	        byte[] encodedSBoxOID  = new ASN1.ObjectIdentifier(parameters.SBoxOID ).Encoded; 

	        // закодировать координаты точки
	        byte[] encodedQX = Math.Convert.FromBigInteger(publicKey.Q.X, Endian); 
	        byte[] encodedQY = Math.Convert.FromBigInteger(publicKey.Q.Y, Endian);

            // определить размер личного ключа в байтах
            int cb = (((GOST.GOSTR3410.IECParameters)parameters).Order.BitLength + 7) / 8; 

	        // определить идентификатор алгоритма
	        ulong keyType = (cb == 32) ? API.CKK_GOSTR3410 : API.CKK_GOSTR3410_512; 

	        // выделить память для кодирования значения
	        byte[] encodedValue = new byte[cb * 2]; 

	        // скопировать координаты точки
	        Array.Copy(encodedQX, 0, encodedValue,  0, encodedQX.Length); 
	        Array.Copy(encodedQY, 0, encodedValue, cb, encodedQY.Length); 

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
		public PublicKey(CAPI.PKCS11.Provider provider, CAPI.PKCS11.SessionObject obj, string keyOID)

            // сохранить переданные параметры
            : base(provider.GetKeyFactory(keyOID))
        {
            CAPI.PKCS11.Attributes keyAttributes = null; 

	        // в зависимости от идентификатора ключа
	        if (keyOID == ASN1.GOST.OID.gostR3410_2012_512)
	        {
		        // преобразовать тип ключа
		        keyAttributes = provider.GetKeyAttributes(obj, 
                    provider.CreateAttribute(API.CKA_GOSTR3410_PARAMS, (byte[])null), 
                    provider.CreateAttribute(API.CKA_VALUE,            (byte[])null) 
                ); 
		        // определить параметры ключа
		        ASN1.ObjectIdentifier paramOID = new ASN1.ObjectIdentifier(
			        ASN1.Encodable.Decode(keyAttributes[API.CKA_GOSTR3410_PARAMS].Value)
                ); 
		        // создать параметры
		        parameters = new GOST.GOSTR3410.ECNamedParameters2012(
                    paramOID.Value, ASN1.GOST.OID.gostR3411_2012_512
                );
	        }
	        // в зависимости от идентификатора ключа
	        else if (keyOID == ASN1.GOST.OID.gostR3410_2012_256) 
	        {
		        // получить атрибуты ключа
		        keyAttributes = provider.GetKeyAttributes(obj,                     
                    provider.CreateAttribute(API.CKA_GOSTR3410_PARAMS, (byte[])null), 
                    provider.CreateAttribute(API.CKA_GOSTR3411_PARAMS, 
                        new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3411_2012_256).Encoded), 
                    provider.CreateAttribute(API.CKA_VALUE, (byte[])null) 
                ); 
		        // определить параметры ключа
		        ASN1.ObjectIdentifier paramOID = new ASN1.ObjectIdentifier(
			        ASN1.Encodable.Decode(keyAttributes[API.CKA_GOSTR3410_PARAMS].Value)
                ); 
		        ASN1.ObjectIdentifier hashOID  = new ASN1.ObjectIdentifier(
			        ASN1.Encodable.Decode(keyAttributes[API.CKA_GOSTR3411_PARAMS].Value)
                ); 
    	        // создать параметры
		        parameters = new GOST.GOSTR3410.ECNamedParameters2012(
                    paramOID.Value, hashOID.Value
                );
            }
	        // в зависимости от идентификатора ключа
	        else if (keyOID == ASN1.GOST.OID.gostR3410_2001) 
	        {
		        // получить атрибуты ключа
		        keyAttributes = provider.GetKeyAttributes(obj,                     
                    provider.CreateAttribute(API.CKA_GOSTR3410_PARAMS, (byte[])null), 
                    provider.CreateAttribute(API.CKA_GOSTR3411_PARAMS, 
                        new ASN1.ObjectIdentifier(ASN1.GOST.OID.hashes_cryptopro).Encoded), 
                    provider.CreateAttribute(API.CKA_GOST28147_PARAMS, 
                        new ASN1.ObjectIdentifier(ASN1.GOST.OID.encrypts_A      ).Encoded), 
                    provider.CreateAttribute(API.CKA_VALUE, (byte[])null) 
                ); 
		        // определить параметры ключа
		        ASN1.ObjectIdentifier paramOID = new ASN1.ObjectIdentifier(
			        ASN1.Encodable.Decode(keyAttributes[API.CKA_GOSTR3410_PARAMS].Value)
                ); 
		        ASN1.ObjectIdentifier hashOID  = new ASN1.ObjectIdentifier(
			        ASN1.Encodable.Decode(keyAttributes[API.CKA_GOSTR3411_PARAMS].Value)
                ); 
                // определить параметры ключа
                ASN1.ObjectIdentifier sboxOID  = new ASN1.ObjectIdentifier(
		            ASN1.Encodable.Decode(keyAttributes[API.CKA_GOST28147_PARAMS].Value)
                ); 
		        // создать параметры
		        parameters = new GOST.GOSTR3410.ECNamedParameters2001(
                    paramOID.Value, hashOID.Value, sboxOID.Value
                );
            }
	        // при ошибке выбросить исключение
	        else throw new Aladdin.PKCS11.Exception(API.CKR_KEY_TYPE_INCONSISTENT); 

	        // получить закодированные значения идентификаторов и ключа
	        byte[] encodedValue = keyAttributes[API.CKA_VALUE].Value; int cb = encodedValue.Length;

	        // извлечь координаты точки
	        byte[] qx = new byte[cb / 2]; Array.Copy(encodedValue,      0, qx, 0, cb / 2);  
	        byte[] qy = new byte[cb / 2]; Array.Copy(encodedValue, cb / 2, qy, 0, cb / 2); 

	        // раскодировать координаты точки
	        q = new EC.Point(
                Math.Convert.ToBigInteger(qx, Endian), 
                Math.Convert.ToBigInteger(qy, Endian)
            );
        }
        // параметры ключа
        public override IParameters Parameters { get { return parameters; }}
		// координаты X и Y точки
		public EC.Point Q { get { return q; }}	
	}
}
