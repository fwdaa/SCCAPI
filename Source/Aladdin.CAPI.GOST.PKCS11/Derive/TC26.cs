using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.GOST.PKCS11.Derive
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм диверсификации ключа
    ///////////////////////////////////////////////////////////////////////////
    public class KeyDiversify2012 : CAPI.PKCS11.KeyDerive
    {
	    // конструктор
	    public KeyDiversify2012(CAPI.PKCS11.Applet applet) : base(applet) {} 
    
	    // параметры алгоритма
	    protected override Mechanism GetParameters(CAPI.PKCS11.Session sesssion, byte[] random)
        {
            // параметры алгоритма
            return new Mechanism(API.CKM_KDF_GOSTR3411_2012_256, random); 
        }
    }
}
