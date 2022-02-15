using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.MAC
{
	///////////////////////////////////////////////////////////////////////////////
	// Алгоритм вычисления имитовставки HMAC SHA2-512
	///////////////////////////////////////////////////////////////////////////////
	public class HMAC_SHA2_512 : HMAC
	{
		// конструктор
        public HMAC_SHA2_512(CAPI.PKCS11.Applet applet) : this(applet, 64) {}

		// конструктор
		public HMAC_SHA2_512(CAPI.PKCS11.Applet applet, int macSize) 
            
            // сохранить переданные параметры
            : base(applet, API.CKM_SHA512_HMAC, API.CKM_SHA512, API.CKK_SHA512_HMAC, macSize) {}
    }
}
