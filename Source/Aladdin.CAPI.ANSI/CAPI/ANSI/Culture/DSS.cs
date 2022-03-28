namespace Aladdin.CAPI.ANSI.Culture
{
    ///////////////////////////////////////////////////////////////////////////
    // Национальные особенности DSS
    ///////////////////////////////////////////////////////////////////////////
    public class DSS : CAPI.Culture
    {
        // параметры алгоритмов
        public override ASN1.ISO.AlgorithmIdentifier HashAlgorithm(IRand rand) 
        { 
            // вернуть параметры алгоритма
            return new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_sha1),
                ASN1.Null.Instance
            ); 
        }
        public override ASN1.ISO.AlgorithmIdentifier HMacAlgorithm(IRand rand)
        { 
            // вернуть параметры алгоритма
            return new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.rsa_hmac_sha1),
                ASN1.Null.Instance
             ); 
        }
        public override ASN1.ISO.AlgorithmIdentifier CipherAlgorithm(IRand rand) 
        { 
		    // сгенерировать синхропосылку
		    byte[] iv = new byte[8]; rand.Generate(iv, 0, iv.Length); 

            // вернуть параметры алгоритма
            return new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.rsa_tdes192_cbc),
                new ASN1.OctetString(iv)
            ); 
        }
        public override ASN1.ISO.AlgorithmIdentifier KeyWrapAlgorithm(IRand rand) 
        { 
            // вернуть параметры алгоритма
            return new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS9.OID.smime_tdes192_wrap),
                ASN1.Null.Instance
            ); 
        }
        public override ASN1.ISO.AlgorithmIdentifier SignHashAlgorithm(IRand rand) 
        {
            // вернуть параметры алгоритма
            return new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.x957_dsa_sha1), null
            ); 
        }
        public override ASN1.ISO.AlgorithmIdentifier SignDataAlgorithm(IRand rand) 
        {
            // вернуть параметры алгоритма
            return new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.x957_dsa_sha1), null
            ); 
        }
        public override ASN1.ISO.AlgorithmIdentifier TransportAgreementAlgorithm(IRand rand) 
        { 
            // вернуть параметры алгоритма
            return new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS9.OID.smime_esdh),
                KeyWrapAlgorithm(rand)
            ); 
        }
        // параметры шифрования по паролю
        public override PBE.PBECulture PBE(PBE.PBEParameters parameters)
        {
            // вернуть параметры шифрования по паролю
            return new PKCS12(parameters); 
        }
        ///////////////////////////////////////////////////////////////////////////
        // Парольная защита
        ///////////////////////////////////////////////////////////////////////////
        public class PKCS12 : PBE.PBECulture
        {
            // конструктор
            public PKCS12(PBE.PBEParameters parameters) : base(parameters) {} 
        
            // параметры алгоритма хэширования
            public override ASN1.ISO.AlgorithmIdentifier HashAlgorithm(IRand rand) 
            { 
                // параметры алгоритма хэширования
                return new DSS().HashAlgorithm(rand); 
            }
            // параметры алгоритма шифрования
            public override ASN1.ISO.AlgorithmIdentifier CipherAlgorithm(IRand rand)
            { 
                // указать число итераций
                int iterations = PBEParameters.PBEIterations; 

                // выделить буфер для случайных данных
                byte[] salt = new byte[PBEParameters.PBESaltLength]; 
                    
                // сгенерировать случайные данные
                rand.Generate(salt, 0, salt.Length); 

                // вернуть параметры алгоритма
                return new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(
                        ASN1.ISO.PKCS.PKCS12.OID.pbe_sha1_tdes_192_cbc),
                    new ASN1.ISO.PKCS.PKCS5.PBEParameter(
                        new ASN1.OctetString(salt), new ASN1.Integer(iterations)
                    )
                ); 
            }
        }
    }
}
