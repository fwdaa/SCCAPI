using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.Sign.ECDSA
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм подписи хэш-значения DSA
    ///////////////////////////////////////////////////////////////////////////
    public class VerifyHash : CAPI.PKCS11.VerifyHash
    {
        // способ кодирования чисел
        private const Math.Endian Endian = Math.Endian.BigEndian; 
    
        // конструктор
	    public VerifyHash(CAPI.PKCS11.Applet applet) : base(applet) {} 

	    // параметры алгоритма
        protected override Mechanism GetParameters(
            CAPI.PKCS11.Session sesssion, IParameters parameters)
	    {
		    // параметры алгоритма
		    return new Mechanism(API.CKM_ECDSA); 
	    }
	    // алгоритм проверки подписи хэш-значения
	    public override void Verify(IPublicKey publicKey, 
            ASN1.ISO.AlgorithmIdentifier hashAgorithm, byte[] hash, byte[] signature) 
        {
            // преобразовать параметры алгоритма
            ANSI.X962.IParameters parameters = (ANSI.X962.IParameters)publicKey.Parameters; 
        
            // раскодировать значение подписи
            ASN1.ANSI.X962.ECDSASigValue encoded = 
                new ASN1.ANSI.X962.ECDSASigValue(ASN1.Encodable.Decode(signature)); 

            // закодировать подпись
            signature = X962.Encoding.EncodeSignature(parameters, encoded); 
        
            // проверить подпись
            base.Verify(publicKey, hashAgorithm, hash, signature); 
        }
    }
}
