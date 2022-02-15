using System;
using Aladdin.PKCS11;

namespace Aladdin.CAPI.GOST.PKCS11.MAC
{
	///////////////////////////////////////////////////////////////////////////////
	// Алгоритм вычисления имитовставки HMAC ГОСТ R 34.11-2012
	///////////////////////////////////////////////////////////////////////////////
	public class HMAC_GOSTR3411_2012 : CAPI.PKCS11.MAC.HMAC
	{
		// число битов и алгоритм хэширования
		private int bits; private CAPI.Hash hashAlgorithm; 

		// конструктор
		public HMAC_GOSTR3411_2012(CAPI.PKCS11.Applet applet, int bits)
			
			// сохранить переданные параметры
			: base(applet, bits / 8) { this.bits = bits; 

			// создать алгоритм хэширования
			hashAlgorithm = new Hash.GOSTR3411_2012(applet, bits); 
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
			// указать параметры алгоритма
			return new Mechanism(bits == 256 ? 
                API.CKM_GOSTR3411_2012_256_HMAC : API.CKM_GOSTR3411_2012_512_HMAC
            ); 
		}
	}
}
