using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.MAC
{
	///////////////////////////////////////////////////////////////////////////////
	// Алгоритм вычисления имитовставки HMAC RIPEMD-128
	///////////////////////////////////////////////////////////////////////////////
	public class HMAC_RIPEMD128 : HMAC
	{
		// конструктор
        public HMAC_RIPEMD128(CAPI.PKCS11.Applet applet) : this(applet, 16) {}

		// конструктор
		public HMAC_RIPEMD128(CAPI.PKCS11.Applet applet, int macSize) 
            
            // сохранить переданные параметры
            : base(applet, API.CKM_RIPEMD128_HMAC, API.CKM_RIPEMD128, API.CKK_RIPEMD128_HMAC, macSize) {}
    }
}
