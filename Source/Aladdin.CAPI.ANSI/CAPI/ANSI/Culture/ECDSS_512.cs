namespace Aladdin.CAPI.ANSI
{
    ///////////////////////////////////////////////////////////////////////////
    // Национальные особенности ECDSS (512 бит)
    ///////////////////////////////////////////////////////////////////////////
    public class ECDSS_512 : CAPI.Culture
    {
        // параметры алгоритмов
        public override ASN1.ISO.AlgorithmIdentifier HashAlgorithm(IRand rand) 
        { 
            // вернуть параметры алгоритма
            return new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_512),
                ASN1.Null.Instance
            ); 
        }
        public override ASN1.ISO.AlgorithmIdentifier HMacAlgorithm(IRand rand) 
        { 
            // вернуть параметры алгоритма
            return new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.rsa_hmac_sha2_512),
                ASN1.Null.Instance
            ); 
        }
        public override ASN1.ISO.AlgorithmIdentifier CipherAlgorithm(IRand rand) 
        { 
		    // сгенерировать синхропосылку
		    byte[] iv = new byte[16]; rand.Generate(iv, 0, iv.Length); 

            // вернуть параметры алгоритма
            return new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_aes256_cbc),
                new ASN1.OctetString(iv)
            ); 
        }
        public override ASN1.ISO.AlgorithmIdentifier KeyWrapAlgorithm(IRand rand) 
        { 
            // вернуть параметры алгоритма
            return new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_aes256_wrap),
                ASN1.Null.Instance
            ); 
        }
        public override ASN1.ISO.AlgorithmIdentifier SignHashAlgorithm(IRand rand) 
        {
            // вернуть параметры алгоритма
            return new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.x962_ecdsa_recommended), null
            ); 
        }
        public override ASN1.ISO.AlgorithmIdentifier SignDataAlgorithm(IRand rand) 
        {
            // вернуть параметры алгоритма
            return new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.x962_ecdsa_sha2_512), null
            ); 
        }
        public override ASN1.ISO.AlgorithmIdentifier TransportAgreementAlgorithm(IRand rand) 
        { 
            // вернуть параметры алгоритма
            return new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.certicom_ecdh_std_sha2_512),
                KeyWrapAlgorithm(rand)
            ); 
        }
        ///////////////////////////////////////////////////////////////////////////
        // Парольная защита
        ///////////////////////////////////////////////////////////////////////////
        public class PKCS12 : PBE.PBEDefaultCulture
        {
            // конструктор
            public PKCS12(PBE.PBEParameters parameters) : base(new ECDSS_512(), parameters, true) {}
        }
    }
}
