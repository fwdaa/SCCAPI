///////////////////////////////////////////////////////////////////////////
// Национальные особенности
///////////////////////////////////////////////////////////////////////////
namespace Aladdin.CAPI.GOST.Culture
{
    ///////////////////////////////////////////////////////////////////////////
    // Национальные особенности ГОСТ R34.10-2012 (256 бит)
    ///////////////////////////////////////////////////////////////////////////
    public class GOSTR2012_256 : GOST28147
    {
        // конструктор
        public GOSTR2012_256() : base(ASN1.GOST.OID.encrypts_tc26_z) {}

        // параметры алгоритмов
        public override ASN1.ISO.AlgorithmIdentifier HashAlgorithm(IRand rand) 
        { 
            // вернуть параметры алгоритма
            return new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3411_2012_256),
                ASN1.Null.Instance
            ); 
        }
        public override ASN1.ISO.AlgorithmIdentifier HMacAlgorithm(IRand rand)
        { 
            // вернуть параметры алгоритма
            return new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3411_2012_HMAC_256), 
                ASN1.Null.Instance
            ); 
        }
        public override ASN1.ISO.AlgorithmIdentifier SignHashAlgorithm(IRand rand) 
        { 
            // вернуть параметры алгоритма
            return new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3410_2012_256),
                ASN1.Null.Instance
            ); 
        }
        public override ASN1.ISO.AlgorithmIdentifier SignDataAlgorithm(IRand rand) 
        {
            // вернуть параметры алгоритма
            return new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3411_2012_R3410_2012_256), null
            ); 
        }
        public override ASN1.ISO.AlgorithmIdentifier TransportKeyAlgorithm(IRand rand) 
        { 
            // вернуть параметры алгоритма
            return new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3410_2012_256),
                ASN1.Null.Instance
            ); 
        }
        public override ASN1.ISO.AlgorithmIdentifier TransportAgreementAlgorithm(IRand rand) 
        { 
            // вернуть параметры алгоритма
            return new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3410_2012_DH_256),
                KeyWrapAlgorithm(rand)
            ); 
        }
        ///////////////////////////////////////////////////////////////////////////
        // Парольная защита
        ///////////////////////////////////////////////////////////////////////////
        public class PKCS12 : PBE.PBECulture.Default
        {
            // конструктор
            public PKCS12(PBE.PBEParameters parameters) 
                
                // сохранить переданные параметры
                : base(new GOSTR2012_256(), parameters, true) {} 
        }
    }
}

