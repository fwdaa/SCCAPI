using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.MAC
{
	///////////////////////////////////////////////////////////////////////////////
	// Алгоритм вычисления имитовставки HMAC SHA2-512/256
	///////////////////////////////////////////////////////////////////////////////
	public class HMAC_SHA2_512_256 : HMAC
	{
		// конструктор
        public HMAC_SHA2_512_256(CAPI.PKCS11.Applet applet) : this(applet, 32) {}

		// конструктор
		public HMAC_SHA2_512_256(CAPI.PKCS11.Applet applet, int macSize) 
            
            // сохранить переданные параметры
            : base(applet, API.CKM_SHA512_256_HMAC, API.CKM_SHA512_256, macSize) {}
    }
}
