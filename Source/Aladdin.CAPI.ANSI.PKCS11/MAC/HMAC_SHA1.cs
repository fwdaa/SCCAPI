using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.MAC
{
	///////////////////////////////////////////////////////////////////////////////
	// Алгоритм вычисления имитовставки HMAC SHA1
	///////////////////////////////////////////////////////////////////////////////
	public class HMAC_SHA1 : HMAC
	{
		// конструктор
        public HMAC_SHA1(CAPI.PKCS11.Applet applet) : this(applet, 20) {}

		// конструктор
		public HMAC_SHA1(CAPI.PKCS11.Applet applet, int macSize) 
            
            // сохранить переданные параметры
            : base(applet, API.CKM_SHA_1_HMAC, API.CKM_SHA_1, API.CKK_SHA_1_HMAC, macSize) {}
    }
}
