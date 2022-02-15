using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.Sign.RSA
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм подписи RSA PKCS1
    ///////////////////////////////////////////////////////////////////////////
    public class SignData : CAPI.PKCS11.SignData
    {
        // конструктор
	    public SignData(CAPI.PKCS11.Applet applet, ulong algID) 
    
            // сохранить переданные параметры
            : base(applet) { this.algID = algID; } private ulong algID; 

	    // параметры алгоритма
        protected override Mechanism GetParameters(
            CAPI.PKCS11.Session sesssion, IParameters parameters)
	    {
		    // параметры алгоритма
		    return new Mechanism(algID); 
	    }
    }
}
