using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.Sign.RSA.PSS
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм проверки подписи RSA PSS
    ///////////////////////////////////////////////////////////////////////////
    public class VerifyHash : CAPI.PKCS11.VerifyHash
    {
        // параметры алгоритма
        private ulong hashAlg; private ulong mgf; private int saltLength; 
    
        // конструктор
	    public VerifyHash(CAPI.PKCS11.Applet applet, 
            ulong hashAlg, ulong mgf, int saltLength) : base(applet)
        { 
            // сохранить переданные параметры
            this.hashAlg = hashAlg; this.mgf = mgf; this.saltLength = saltLength;
        } 
	    // параметры алгоритма
        protected override Mechanism GetParameters(
            CAPI.PKCS11.Session sesssion, IParameters parameters)
	    {
            // указать параметры алгоритма
            Parameters.CK_RSA_PKCS_PSS_PARAMS pssParameters = 
                new Parameters.CK_RSA_PKCS_PSS_PARAMS(hashAlg, mgf, saltLength); 

            // вернуть параметры алгоритма
            return new Mechanism(API.CKM_RSA_PKCS_PSS, pssParameters); 
	    }
    }
}
