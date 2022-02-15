package aladdin.capi.ansi.pkcs11.keyx.rsa;
import aladdin.capi.*;
import aladdin.capi.pkcs11.*;
import aladdin.pkcs11.*;

///////////////////////////////////////////////////////////////////////////
// Алгоритм расшифрования RSA
///////////////////////////////////////////////////////////////////////////
public class Decipherment extends aladdin.capi.pkcs11.Decipherment
{
    // конструктор
	public Decipherment(Applet applet) { super(applet); } 
    
	// параметры алгоритма
    @Override protected Mechanism getParameters(Session session, IParameters parameters)
	{
		// параметры алгоритма
		return new Mechanism(API.CKM_RSA_X_509); 
	}
}
