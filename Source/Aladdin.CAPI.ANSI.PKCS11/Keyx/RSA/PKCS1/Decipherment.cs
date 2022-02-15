using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.Keyx.RSA.PKCS1
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм расшифрования RSA PKCS1
    ///////////////////////////////////////////////////////////////////////////
    public class Decipherment : CAPI.PKCS11.Decipherment
    {
        // конструктор
	    public Decipherment(CAPI.PKCS11.Applet applet) : base(applet) {} 
    
	    // параметры алгоритма
        protected override Mechanism GetParameters(
            CAPI.PKCS11.Session session, IParameters parameters)
	    {
		    // параметры алгоритма
		    return new Mechanism(API.CKM_RSA_PKCS); 
	    }
    }
}
