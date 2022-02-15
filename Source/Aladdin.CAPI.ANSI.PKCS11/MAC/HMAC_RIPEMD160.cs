using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.MAC
{
	///////////////////////////////////////////////////////////////////////////////
	// Алгоритм вычисления имитовставки HMAC RIPEMD-160
	///////////////////////////////////////////////////////////////////////////////
	public class HMAC_RIPEMD160 : HMAC
	{
		// конструктор
        public HMAC_RIPEMD160(CAPI.PKCS11.Applet applet) : this(applet, 20) {}

		// конструктор
		public HMAC_RIPEMD160(CAPI.PKCS11.Applet applet, int macSize) 
            
            // сохранить переданные параметры
            : base(applet, API.CKM_RIPEMD160_HMAC, API.CKM_RIPEMD160, API.CKK_RIPEMD160_HMAC, macSize) {}
    }
}
