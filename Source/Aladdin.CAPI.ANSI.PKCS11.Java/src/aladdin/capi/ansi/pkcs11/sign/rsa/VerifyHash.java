package aladdin.capi.ansi.pkcs11.sign.rsa;
import aladdin.capi.*; 
import aladdin.capi.pkcs11.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм подписи хэш-значения RSA
///////////////////////////////////////////////////////////////////////////
public class VerifyHash extends aladdin.capi.pkcs11.VerifyHash
{
    // конструктор
	public VerifyHash(Applet applet, long algID) 
    
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
