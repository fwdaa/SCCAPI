using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.MAC
{
	///////////////////////////////////////////////////////////////////////////////
	// Алгоритм вычисления имитовставки HMAC SHA2-224
	///////////////////////////////////////////////////////////////////////////////
	public class HMAC_SHA2_224 : HMAC
	{
		// конструктор
        public HMAC_SHA2_224(CAPI.PKCS11.Applet applet) : this(applet, 28) {}

		// конструктор
		public HMAC_SHA2_224(CAPI.PKCS11.Applet applet, int macSize) 
            
            // сохранить переданные параметры
            : base(applet, API.CKM_SHA224_HMAC, API.CKM_SHA224, API.CKK_SHA224_HMAC, macSize) {}
    }
}
