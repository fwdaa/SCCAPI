using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.MAC
{
	///////////////////////////////////////////////////////////////////////////////
	// Алгоритм вычисления имитовставки HMAC SHA2-384
	///////////////////////////////////////////////////////////////////////////////
	public class HMAC_SHA2_384 : HMAC
	{
		// конструктор
        public HMAC_SHA2_384(CAPI.PKCS11.Applet applet) : this(applet, 48) {}

		// конструктор
		public HMAC_SHA2_384(CAPI.PKCS11.Applet applet, int macSize) 
            
            // сохранить переданные параметры
            : base(applet, API.CKM_SHA384_HMAC, API.CKM_SHA384, API.CKK_SHA384_HMAC, macSize) {}
    }
}
