using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.MAC
{
	///////////////////////////////////////////////////////////////////////////////
	// Алгоритм вычисления имитовставки HMAC MD2
	///////////////////////////////////////////////////////////////////////////////
	public class HMAC_MD2 : HMAC
	{
		// конструктор
        public HMAC_MD2(CAPI.PKCS11.Applet applet) : this(applet, 16) {}

		// конструктор
		public HMAC_MD2(CAPI.PKCS11.Applet applet, int macSize) 
            
            // сохранить переданные параметры
            : base(applet, API.CKM_MD2_HMAC, API.CKM_MD2, macSize) {}
	}
}
