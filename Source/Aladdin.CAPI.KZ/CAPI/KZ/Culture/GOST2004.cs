namespace Aladdin.CAPI.KZ.Culture
{
    ///////////////////////////////////////////////////////////////////////////
    // Национальные особенности ГОСТ
    ///////////////////////////////////////////////////////////////////////////
    public class GOST2004 : CAPI.Culture
    {
        // параметры алгоритмов
        public override ASN1.ISO.AlgorithmIdentifier HashAlgorithm(IRand rand) 
        { 
            // вернуть параметры алгоритма
            return new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.KZ.OID.gamma_gost34311_95),
                ASN1.Null.Instance
            ); 
        }
        public override ASN1.ISO.AlgorithmIdentifier CipherAlgorithm(IRand rand) 
        { 
	        // сгенерировать синхропосылку
	        byte[] iv = new byte[8]; rand.Generate(iv, 0, iv.Length); 

            // вернуть параметры алгоритма
            return new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.KZ.OID.gamma_cipher_gost),
                new ASN1.OctetString(iv)
            ); 
        }
        public override ASN1.ISO.AlgorithmIdentifier KeyWrapAlgorithm(IRand rand) 
        { 
	        // сгенерировать синхропосылку
	        byte[] iv = new byte[8]; rand.Generate(iv, 0, iv.Length); 

            // вернуть параметры алгоритма
            return new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.KZ.OID.gamma_cipher_gost),
                new ASN1.OctetString(iv)
            ); 
        }
        // параметры алгоритм подписи хэш-значения
	    public override ASN1.ISO.AlgorithmIdentifier SignHashAlgorithm(IRand rand)
        {
            // вернуть параметры алгоритма
            return new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.KZ.OID.gamma_gost34310_2004), ASN1.Null.Instance
            ); 
        }
        public override ASN1.ISO.AlgorithmIdentifier SignDataAlgorithm(IRand rand) 
        {
            // вернуть параметры алгоритма
            return new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.KZ.OID.gamma_gost34310_34311_2004_t), null
            ); 
        }
        public override ASN1.ISO.AlgorithmIdentifier TransportAgreementAlgorithm(IRand rand) 
        { 
            // вернуть параметры алгоритма
            return new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.KZ.OID.gamma_gost28147),
                ASN1.Null.Instance
            ); 
        }
        ///////////////////////////////////////////////////////////////////////////
        // Парольная защита
        ///////////////////////////////////////////////////////////////////////////
        public class PKCS12 : PBE.PBECulture
        {
            // национальные особенности
            private CAPI.Culture culture; 

            // конструктор
            public PKCS12(PBE.PBEParameters parameters) 
                
                // сохранить переданные параметры
                : base(parameters) { culture = new GOST2004(); } 
            
            // национальные особенности
            protected override CAPI.Culture BaseCulture { get { return culture; }} 

            // параметры алгоритмов
            public override ASN1.ISO.AlgorithmIdentifier HMacAlgorithm(IRand rand)
            { 
                // вернуть параметры алгоритма
                return new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(ASN1.KZ.OID.gamma_hmac_gost34311_95_t), 
                    ASN1.Null.Instance
                ); 
            }
        }
    }
}
