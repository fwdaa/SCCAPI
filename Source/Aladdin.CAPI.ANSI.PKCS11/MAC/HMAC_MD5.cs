using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.MAC
{
	///////////////////////////////////////////////////////////////////////////////
	// Алгоритм вычисления имитовставки HMAC MD5
	///////////////////////////////////////////////////////////////////////////////
	public class HMAC_MD5 : HMAC
	{
		// конструктор
        public HMAC_MD5(CAPI.PKCS11.Applet applet) : this(applet, 16) {}

		// конструктор
		public HMAC_MD5(CAPI.PKCS11.Applet applet, int macSize) 
            
            // сохранить переданные параметры
            : base(applet, API.CKM_MD5_HMAC, API.CKM_MD5, API.CKK_MD5_HMAC, macSize) {}
    }
}
