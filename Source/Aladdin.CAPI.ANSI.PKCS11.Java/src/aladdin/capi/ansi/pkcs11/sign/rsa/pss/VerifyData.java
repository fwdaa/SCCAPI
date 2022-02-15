package aladdin.capi.ansi.pkcs11.sign.rsa.pss;
import aladdin.pkcs11.*;
import aladdin.pkcs11.jni.*;
import aladdin.capi.*;
import aladdin.capi.pkcs11.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Алгоритм проверки подписи RSA PSS
///////////////////////////////////////////////////////////////////////////
public class VerifyData extends aladdin.capi.pkcs11.VerifyData
{
    // идентификатор алгоритма подписи и хэширования
    private final long signAlg; private final long hashAlg;
    // идентификатор алгоритма масирования и размер случайных данных
    private final long mgf; private final int saltLength; 
    
    // конструктор
	public VerifyData(Applet applet, long hashAlg, long mgf, int saltLength) throws IOException
    { 
        // сохранить переданные параметры
        super(applet); this.hashAlg = hashAlg; this.mgf = mgf; this.saltLength = saltLength; 
        
        // определить идентификатор алгоритма
        if (hashAlg == API.CKM_SHA_1   ) signAlg = API.CKM_SHA1_RSA_PKCS_PSS;     else 
        if (hashAlg == API.CKM_SHA224  ) signAlg = API.CKM_SHA224_RSA_PKCS_PSS;   else 
        if (hashAlg == API.CKM_SHA256  ) signAlg = API.CKM_SHA256_RSA_PKCS_PSS;   else 
        if (hashAlg == API.CKM_SHA384  ) signAlg = API.CKM_SHA384_RSA_PKCS_PSS;   else 
        if (hashAlg == API.CKM_SHA512  ) signAlg = API.CKM_SHA512_RSA_PKCS_PSS;   else
        if (hashAlg == API.CKM_SHA3_224) signAlg = API.CKM_SHA3_224_RSA_PKCS_PSS; else 
        if (hashAlg == API.CKM_SHA3_256) signAlg = API.CKM_SHA3_256_RSA_PKCS_PSS; else 
        if (hashAlg == API.CKM_SHA3_384) signAlg = API.CKM_SHA3_384_RSA_PKCS_PSS; else 
        if (hashAlg == API.CKM_SHA3_512) signAlg = API.CKM_SHA3_512_RSA_PKCS_PSS; 
        
        // при ошибке выбросить исключение
        else throw new UnsupportedOperationException();
    } 
	// параметры алгоритма
    @Override 
    protected Mechanism getParameters(Session sesssion, IParameters parameters)
	{
        // указать параметры алгоритма
        CK_RSA_PKCS_PSS_PARAMS pssParameters = new CK_RSA_PKCS_PSS_PARAMS(hashAlg, mgf, saltLength); 
        
		// параметры алгоритма
		return new Mechanism(signAlg, pssParameters); 
	}
}
