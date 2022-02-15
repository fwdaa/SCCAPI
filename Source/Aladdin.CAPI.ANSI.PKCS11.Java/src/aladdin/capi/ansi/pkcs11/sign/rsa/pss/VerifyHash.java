package aladdin.capi.ansi.pkcs11.sign.rsa.pss;
import aladdin.pkcs11.*;
import aladdin.pkcs11.jni.*;
import aladdin.capi.*;
import aladdin.capi.pkcs11.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм проверки подписи RSA PSS
///////////////////////////////////////////////////////////////////////////
public class VerifyHash extends aladdin.capi.pkcs11.VerifyHash
{
    // параметры алгоритма
    private final long hashAlg; private final long mgf; private final int saltLength; 
    
    // конструктор
	public VerifyHash(Applet applet, long hashAlg, long mgf, int saltLength) throws IOException
    { 
        // сохранить переданные параметры
        super(applet); this.hashAlg = hashAlg; this.mgf = mgf; this.saltLength = saltLength;
    } 
	// параметры алгоритма
    @Override 
    protected Mechanism getParameters(Session sesssion, IParameters parameters)
	{
        // указать параметры алгоритма
        CK_RSA_PKCS_PSS_PARAMS pssParameters = new CK_RSA_PKCS_PSS_PARAMS(hashAlg, mgf, saltLength); 
        
		// параметры алгоритма
		return new Mechanism(API.CKM_RSA_PKCS_PSS, pssParameters); 
	}
}
