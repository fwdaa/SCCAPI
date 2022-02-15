package aladdin.capi.ansi.pkcs11.sign.rsa;
import aladdin.asn1.iso.*;
import aladdin.capi.*; 
import aladdin.capi.pkcs11.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм подписи хэш-значения RSA
///////////////////////////////////////////////////////////////////////////
public class SignHash extends aladdin.capi.pkcs11.SignHash
{
    // конструктор
	public SignHash(Applet applet, long algID) 
    
        // сохранить переданные параметры
        { super(applet); this.algID = algID; } private final long algID; 

	// параметры алгоритма
    @Override 
    protected Mechanism getParameters(Session sesssion, IParameters parameters)
	{
		// параметры алгоритма
		return new Mechanism(algID); 
	}
}
