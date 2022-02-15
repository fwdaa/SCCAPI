using System;
using Aladdin.PKCS11;

namespace Aladdin.CAPI.GOST.PKCS11.Keyx.GOSTR3410
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм обмена ГОСТ Р 34.10-2001
	///////////////////////////////////////////////////////////////////////////
	public class TransportKeyUnwrap : CAPI.PKCS11.TransportKeyUnwrap
	{
		// конструктор
		public TransportKeyUnwrap(CAPI.PKCS11.Applet applet) : base(applet) {}

		// получить параметры
		protected override Mechanism GetParameters(CAPI.PKCS11.Session session, 
			IParameters parameters, TransportKeyData data)
        {
	        // раскодировать зашифрованный ключ с параметрами
            ASN1.GOST.GOSTR3410KeyTransport encodedEncryptedKey = 
		        new ASN1.GOST.GOSTR3410KeyTransport(ASN1.Encodable.Decode(data.EncryptedKey));

            // указать идентификатор алгоритма
            ulong algID = API.CKM_GOSTR3410_KEY_WRAP; 

	        // при отсутствии параметров транспортировки
	        if (encodedEncryptedKey.TransportParameters == null)
            {
                // указать параметры алгоритма
                Parameters.CK_GOSTR3410_KEY_WRAP_PARAMS wrapParameters = 
                    new Parameters.CK_GOSTR3410_KEY_WRAP_PARAMS(null, null, 0); 

                // вернуть параметры алгоритма
                return new Mechanism(API.CKM_GOSTR3410_KEY_WRAP, wrapParameters); 
            }
	        else {
		        // извлечь параметры транспортировки
		        ASN1.GOST.GOSTR3410TransportParameters transportParameters = 
			        encodedEncryptedKey.TransportParameters; 

		        // указать идентификатор таблицы подстановок
		        byte[] wrapOID = transportParameters.EncryptionParamSet.Encoded; 

		        // указать случайные данные
		        byte[] ukm = transportParameters.Ukm.Value; UInt64 hPublicKey = 0;

		        // при наличии открытого ключа
		        if (transportParameters.EphemeralPublicKey != null)
		        {
			        // указать дополнительные атрибуты ключа
			        CAPI.PKCS11.Attribute[] keyAttributes = new CAPI.PKCS11.Attribute[] {
				        Applet.Provider.CreateAttribute(API.CKA_UNWRAP, API.CK_TRUE)
			        }; 
			        // извлечь описание открытого ключа
			        ASN1.ISO.PKIX.SubjectPublicKeyInfo publicKeyInfo = 
				        transportParameters.EphemeralPublicKey; 

			        // раскодировать открытый ключ
			        IPublicKey publicKey = Applet.Provider.DecodePublicKey(publicKeyInfo); 

                    // получить информацию алгоритма
                    MechanismInfo info = Applet.GetAlgorithmInfo(algID); 

			        // указать идентификатор ключа
			        hPublicKey = Applet.Provider.ToSessionObject(
                        session, publicKey, info, keyAttributes).Handle; 
		        }
                // указать параметры алгоритма
                Parameters.CK_GOSTR3410_KEY_WRAP_PARAMS wrapParameters = 
                    new Parameters.CK_GOSTR3410_KEY_WRAP_PARAMS(wrapOID, ukm, hPublicKey); 

                // вернуть параметры алгоритма
                return new Mechanism(algID, wrapParameters); 
	        }
        }
	}
}
