namespace Aladdin.CAPI.STB.Culture
{
    ///////////////////////////////////////////////////////////////////////////
    // Национальные особенности STB34101
    ///////////////////////////////////////////////////////////////////////////
    public abstract class STB34101 : CAPI.Culture
    {
        // параметры алгоритмов
        public override ASN1.ISO.AlgorithmIdentifier HashAlgorithm(IRand rand) 
        { 
            // вернуть параметры алгоритма
            return new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.STB.OID.stb34101_belt_hash),
                ASN1.Null.Instance
            ); 
        }
        public override ASN1.ISO.AlgorithmIdentifier SignHashAlgorithm(IRand rand) 
        {
            // вернуть параметры алгоритма
            return new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.STB.OID.stb34101_bign_hbelt), null
            ); 
        }
        public override ASN1.ISO.AlgorithmIdentifier SignDataAlgorithm(IRand rand) 
        {
            // вернуть параметры алгоритма
            return new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.STB.OID.stb34101_bign_hbelt), null
            ); 
        }
        public override ASN1.ISO.AlgorithmIdentifier TransportKeyAlgorithm(IRand rand) 
        { 
            // вернуть параметры алгоритма
            return new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.STB.OID.stb34101_bign_keyTransport),
                ASN1.Null.Instance
            ); 
        }
        ///////////////////////////////////////////////////////////////////////////
        // Парольная защита
        ///////////////////////////////////////////////////////////////////////////
        public abstract class PKCS12 : PBE.PBECulture
        {
            // конструктор
            public PKCS12(PBE.PBEParameters parameters) : base(parameters) {} 

            // параметры алгоритмов
            public override ASN1.ISO.AlgorithmIdentifier HMacAlgorithm(IRand rand)
            { 
                // вернуть параметры алгоритма
                return new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(ASN1.STB.OID.stb34101_hmac_hbelt), 
                    ASN1.Null.Instance
                ); 
            }
        }
    }
}
