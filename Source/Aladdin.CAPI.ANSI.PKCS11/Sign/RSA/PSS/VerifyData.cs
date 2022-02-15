using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.Sign.RSA.PSS
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм проверки подписи RSA PSS
    ///////////////////////////////////////////////////////////////////////////
    public class VerifyData : CAPI.PKCS11.VerifyData
    {
        // идентификатор алгоритма подписи и хэширования
        private ulong signAlg; private ulong hashAlg;
        // идентификатор алгоритма масирования и размер случайных данных
        private ulong mgf; private int saltLength; 
    
        // конструктор
	    public VerifyData(CAPI.PKCS11.Applet applet, 
            ulong hashAlg, ulong mgf, int saltLength) : base(applet)
        { 
            // сохранить переданные параметры
            this.hashAlg = hashAlg; this.mgf = mgf; this.saltLength = saltLength; 
        
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
            else throw new NotSupportedException();
        } 
	    // параметры алгоритма
        protected override Mechanism GetParameters(
            CAPI.PKCS11.Session sesssion, IParameters parameters)
	    {
            // указать параметры алгоритма
            Parameters.CK_RSA_PKCS_PSS_PARAMS pssParameters = 
                new Parameters.CK_RSA_PKCS_PSS_PARAMS(hashAlg, mgf, saltLength); 
        
		    // параметры алгоритма
		    return new Mechanism(signAlg, pssParameters); 
	    }
    }
}
