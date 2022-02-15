using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.Sign.RSA.PKCS1
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм подписи хэш-значения RSA PKCS1
    ///////////////////////////////////////////////////////////////////////////
    public class SignHash : CAPI.PKCS11.SignHash
    {
        // конструктор
	    public SignHash(CAPI.PKCS11.Applet applet) : base(applet) {} 

	    // параметры алгоритма
        protected override Mechanism GetParameters(
            CAPI.PKCS11.Session sesssion, IParameters parameters)
	    {
		    // параметры алгоритма
		    return new Mechanism(API.CKM_RSA_PKCS); 
	    }
        public override byte[] Sign(IPrivateKey key, IRand rand, 
            ASN1.ISO.AlgorithmIdentifier hashAlgorithm, byte[] hash) 
        {
            // закодировать хэш-значение 
            ASN1.ISO.PKCS.DigestInfo digestInfo = new ASN1.ISO.PKCS.DigestInfo(
                hashAlgorithm, new ASN1.OctetString(hash)
            ); 
            // вызвать базовую функцию
            return base.Sign(key, rand, hashAlgorithm, digestInfo.Encoded); 
        }
    }
}
