using System;
using Aladdin.PKCS11;

namespace Aladdin.CAPI.GOST.PKCS11.MAC
{
	///////////////////////////////////////////////////////////////////////////////
	// Алгоритм вычисления имитовставки HMAC ГОСТ R 34.11-94
	///////////////////////////////////////////////////////////////////////////////
	public class HMAC_GOSTR3411_1994 : CAPI.PKCS11.MAC.HMAC
	{
		// идентификатор параметров и алгоритм хэширования
		private string paramsOID; private CAPI.Hash hashAlgorithm; 

		// конструктор
		public HMAC_GOSTR3411_1994(CAPI.PKCS11.Applet applet, string paramsOID) 
			
			// сохранить переданные параметры
			: base(applet, 32) { this.paramsOID = paramsOID; 

			// создать алгоритм хэширования
			hashAlgorithm = new Hash.GOSTR3411_1994(applet, paramsOID); 
		} 
		// освободить выделенные ресурсы
        protected override void OnDispose() 
        {
            // освободить выделенные ресурсы
            RefObject.Release(hashAlgorithm); base.OnDispose();
        }
        // получить алгоритм хэширования
        protected override CAPI.Hash GetHashAlgorithm() { return hashAlgorithm; } 

		// параметры алгоритма
		protected override Mechanism GetParameters(CAPI.PKCS11.Session session)
		{ 
			// закодировать параметры алгоритма
			byte[] encoded = new ASN1.ObjectIdentifier(paramsOID).Encoded; 

			// вернуть параметры алгоритма
			return new Mechanism(API.CKM_GOSTR3411_HMAC, encoded); 
		}
	}
}
