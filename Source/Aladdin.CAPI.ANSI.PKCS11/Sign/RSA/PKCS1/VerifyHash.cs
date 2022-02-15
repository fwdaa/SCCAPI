using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.Sign.RSA.PKCS1
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм подписи хэш-значения RSA PKCS1
    ///////////////////////////////////////////////////////////////////////////
    public class VerifyHash : CAPI.PKCS11.VerifyHash
    {
        // конструктор
	    public VerifyHash(CAPI.PKCS11.Applet applet) : base(applet) {} 

	    // параметры алгоритма
        protected override Mechanism GetParameters(
            CAPI.PKCS11.Session sesssion, IParameters parameters)
	    {
		    // параметры алгоритма
		    return new Mechanism(API.CKM_RSA_PKCS); 
	    }
        public override void Verify(IPublicKey key, 
            ASN1.ISO.AlgorithmIdentifier hashAlgorithm, byte[] hash, byte[] signature)
        {
            // закодировать хэш-значение 
            ASN1.ISO.PKCS.DigestInfo digestInfo = new ASN1.ISO.PKCS.DigestInfo(
                hashAlgorithm, new ASN1.OctetString(hash)
            ); 
            // вызвать базовую функцию
            base.Verify(key, hashAlgorithm, digestInfo.Encoded, signature);
        }
    }
}
