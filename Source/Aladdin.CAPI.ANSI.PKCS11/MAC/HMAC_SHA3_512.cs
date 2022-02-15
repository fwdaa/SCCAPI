using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.MAC
{
	///////////////////////////////////////////////////////////////////////////////
	// Алгоритм вычисления имитовставки HMAC SHA3-512
	///////////////////////////////////////////////////////////////////////////////
	public class HMAC_SHA3_512 : HMAC
	{
		// конструктор
        public HMAC_SHA3_512(CAPI.PKCS11.Applet applet) : this(applet, 64) {}

		// конструктор
		public HMAC_SHA3_512(CAPI.PKCS11.Applet applet, int macSize) 
            
            // сохранить переданные параметры
            : base(applet, API.CKM_SHA3_512_HMAC, API.CKM_SHA3_512, API.CKK_SHA3_512_HMAC, macSize) {}
    }
}
