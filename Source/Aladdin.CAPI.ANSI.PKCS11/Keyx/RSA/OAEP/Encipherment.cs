using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.Keyx.RSA.OAEP
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм зашифрования RSA OAEP
    ///////////////////////////////////////////////////////////////////////////
    public class Encipherment : CAPI.PKCS11.Encipherment
    {
        // идентификаторы алгоритмов и метка
        private ulong hashAlg; private ulong mgf; private byte[] sourceData; 
    
        // конструктор
	    public Encipherment(CAPI.PKCS11.Applet applet, 
            ulong hashAlg, ulong mgf, byte[] sourceData) : base(applet)
        { 
            // сохранить переданные параметры
            this.hashAlg = hashAlg; this.mgf = mgf; this.sourceData = sourceData; 
        } 
	    // параметры алгоритма
        protected override Mechanism GetParameters(
            CAPI.PKCS11.Session session, IParameters parameters)
	    {
            // указать параметры алгоритма
            Parameters.CK_RSA_PKCS_OAEP_PARAMS oaepParameters = 
                new Parameters.CK_RSA_PKCS_OAEP_PARAMS(hashAlg, mgf, sourceData); 

            // вернуть параметры алгоритма
            return new Mechanism(API.CKM_RSA_PKCS_OAEP, oaepParameters); 
	    }
    }
}
