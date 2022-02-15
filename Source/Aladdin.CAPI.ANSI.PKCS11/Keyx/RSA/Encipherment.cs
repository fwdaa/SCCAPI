using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.Keyx.RSA
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм зашифрования RSA PKCS1
    ///////////////////////////////////////////////////////////////////////////
    public class Encipherment : CAPI.PKCS11.Encipherment
    {
        // конструктор
	    public Encipherment(CAPI.PKCS11.Applet applet) : base(applet) {} 
    
	    // параметры алгоритма
        protected override Mechanism GetParameters(
            CAPI.PKCS11.Session session, IParameters parameters)
	    {
		    // параметры алгоритма
		    return new Mechanism(API.CKM_RSA_X_509); 
	    }
    }
}
