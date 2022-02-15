package aladdin.capi.gost.pkcs11.sign.gostr3410;
import aladdin.capi.*; 
import aladdin.capi.pkcs11.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм подписи ГОСТ R 34.10-2001
///////////////////////////////////////////////////////////////////////////
public class VerifyData extends aladdin.capi.pkcs11.VerifyData
{
    // конструктор
	public VerifyData(Applet applet, long algID) 
    
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
