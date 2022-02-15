namespace Aladdin.CAPI.ANSI.Culture
{
    ///////////////////////////////////////////////////////////////////////////
    // Национальные особенности RSA
    ///////////////////////////////////////////////////////////////////////////
    public class RSAOP : RSA
    {
        // параметры алгоритмов
        public override ASN1.ISO.AlgorithmIdentifier CiphermentAlgorithm(IRand rand) 
        { 
            // вернуть параметры алгоритма
            return new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS1.OID.rsa_oaep),
                new ASN1.ISO.PKCS.PKCS1.RSAESOAEPParams(null, null, null)
            ); 
        }
        public override ASN1.ISO.AlgorithmIdentifier SignHashAlgorithm(IRand rand) 
        { 
            // вернуть параметры алгоритма
            return new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS1.OID.rsa_pss), 
                new ASN1.ISO.PKCS.PKCS1.RSASSAPSSParams(null, null, null, null)
            ); 
        }
        public override ASN1.ISO.AlgorithmIdentifier SignDataAlgorithm(IRand rand) 
        {
            // вернуть параметры алгоритма
            return new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS1.OID.rsa_pss), 
                new ASN1.ISO.PKCS.PKCS1.RSASSAPSSParams(null, null, null, null)
            ); 
        }
    }
}

