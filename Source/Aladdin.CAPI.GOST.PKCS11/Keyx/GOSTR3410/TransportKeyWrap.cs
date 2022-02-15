using System;
using Aladdin.PKCS11;

namespace Aladdin.CAPI.GOST.PKCS11.Keyx.GOSTR3410
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм обмена ГОСТ Р 34.10-2001
	///////////////////////////////////////////////////////////////////////////
	public class TransportKeyWrap : CAPI.PKCS11.TransportKeyWrap
	{
		// размер случайных данных
		private int sizeUKM; 
	
		// конструктор
		public TransportKeyWrap(CAPI.PKCS11.Applet applet, int sizeUKM)

			// сохранить переданные параметры
			: base(applet) { this.sizeUKM = sizeUKM; }

		// получить параметры
		protected override Mechanism GetParameters(
            CAPI.PKCS11.Session session, IParameters parameters, IRand rand)
        {
	        // преобразовать тип параметров
	        GOST.GOSTR3410.INamedParameters gostParameters =
		        (GOST.GOSTR3410.INamedParameters) parameters;

	        // получить идентификатор таблицы подстановок для KEK
	        byte[] sboxOID = (new ASN1.ObjectIdentifier(gostParameters.SBoxOID)).Encoded;

	        // сгенерировать случайные данные
	        byte[] ukm = new byte[sizeUKM]; rand.Generate(ukm, 0, ukm.Length);

            // указать параметры алгоритма
            Parameters.CK_GOSTR3410_KEY_WRAP_PARAMS wrapParameters = 
                new Parameters.CK_GOSTR3410_KEY_WRAP_PARAMS(sboxOID, ukm, 0); 

            // вернуть параметры алгоритма
            return new Mechanism(API.CKM_GOSTR3410_KEY_WRAP, wrapParameters);
        }
	    // действия стороны-отправителя
	    public override TransportKeyData Wrap(
            ASN1.ISO.AlgorithmIdentifier algorithmParameters, 
            IPublicKey publicKey, IRand rand, ISecretKey CEK) 
        {
            // закодировать открытый ключ
            ASN1.ISO.PKIX.SubjectPublicKeyInfo publicKeyInfo = publicKey.Encoded; 

            // вызвать базовую функцию
            return base.Wrap(publicKeyInfo.Algorithm, publicKey, rand, CEK); 
        }

	} 
}
