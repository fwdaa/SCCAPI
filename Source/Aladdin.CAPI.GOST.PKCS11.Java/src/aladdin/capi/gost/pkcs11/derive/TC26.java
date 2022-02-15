package aladdin.capi.gost.pkcs11.derive;
import aladdin.capi.pkcs11.*;
import aladdin.pkcs11.*;

///////////////////////////////////////////////////////////////////////////
// Алгоритм диверсификации ключа
///////////////////////////////////////////////////////////////////////////
public class TC26 extends aladdin.capi.pkcs11.KeyDerive
{
	// конструктор
	public TC26(Applet applet) { super(applet); } 
    
	// параметры алгоритма
	@Override protected Mechanism getParameters(Session sesssion, byte[] random)
    {
        // параметры алгоритма
        return new Mechanism(API.CKM_KDF_GOSTR3411_2012_256, random); 
    }
}
