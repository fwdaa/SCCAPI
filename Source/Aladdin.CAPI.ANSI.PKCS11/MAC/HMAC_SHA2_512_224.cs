using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.MAC
{
	///////////////////////////////////////////////////////////////////////////////
	// Алгоритм вычисления имитовставки HMAC SHA2-512/224
	///////////////////////////////////////////////////////////////////////////////
	public class HMAC_SHA2_512_224 : HMAC
	{
		// конструктор
        public HMAC_SHA2_512_224(CAPI.PKCS11.Applet applet) : this(applet, 28) {}

		// конструктор
		public HMAC_SHA2_512_224(CAPI.PKCS11.Applet applet, int macSize) 
            
            // сохранить переданные параметры
            : base(applet, API.CKM_SHA512_224_HMAC, API.CKM_SHA512_224, macSize) {}
    }
}
