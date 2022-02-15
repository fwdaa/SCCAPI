using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.MAC
{
	///////////////////////////////////////////////////////////////////////////////
	// Алгоритм вычисления имитовставки HMAC SHA2-256
	///////////////////////////////////////////////////////////////////////////////
	public class HMAC_SHA2_256 : HMAC
	{
		// конструктор
        public HMAC_SHA2_256(CAPI.PKCS11.Applet applet) : this(applet, 32) {}

		// конструктор
		public HMAC_SHA2_256(CAPI.PKCS11.Applet applet, int macSize) 
            
            // сохранить переданные параметры
            : base(applet, API.CKM_SHA256_HMAC, API.CKM_SHA256, API.CKK_SHA256_HMAC, macSize) {}
    }
}
