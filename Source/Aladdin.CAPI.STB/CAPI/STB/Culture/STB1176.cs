namespace Aladdin.CAPI.STB.Culture
{
    ///////////////////////////////////////////////////////////////////////////
    // Национальные особенности STB1176 
    ///////////////////////////////////////////////////////////////////////////
    public class STB1176 : CAPI.Culture
    {
        // конструктор
        public STB1176(string sboxParams)
        
            // сохранить переданные параметры
            { this.sboxParams = sboxParams; } private string sboxParams;

        // конструктор
        public STB1176() : this(ASN1.STB.OID.gost28147_sblock_1) {}

        // параметры алгоритмов
        public override ASN1.ISO.AlgorithmIdentifier HashAlgorithm(IRand rand) 
        { 
            // сгенерировать стартовое значение
            byte[] start = new byte[32]; rand.Generate(start, 0, start.Length); 

            // вернуть параметры алгоритма
            return new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.STB.OID.stb11761_hash),
                new ASN1.OctetString(start)
            ); 
        }
        public override ASN1.ISO.AlgorithmIdentifier CipherAlgorithm(IRand rand) 
        { 
            // сгенерировать синхропосылку
            byte[] iv = new byte[8]; rand.Generate(iv, 0, iv.Length); 

            // вернуть параметры алгоритма
            return new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.STB.OID.gost28147_cfb),
                new ASN1.STB.GOSTParams(
                    new ASN1.OctetString(iv), new ASN1.ObjectIdentifier(sboxParams)
                )
            ); 
        }
        public override ASN1.ISO.AlgorithmIdentifier KeyWrapAlgorithm(IRand rand) 
        { 
            // сгенерировать синхропосылку
            byte[] iv = new byte[8]; rand.Generate(iv, 0, iv.Length); 

            // вернуть параметры алгоритма
            return new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.STB.OID.gost28147_cfb),
                new ASN1.STB.GOSTParams(
                    new ASN1.OctetString(iv), new ASN1.ObjectIdentifier(sboxParams)
                )
            ); 
        }
        public override ASN1.ISO.AlgorithmIdentifier SignHashAlgorithm(IRand rand) 
        {
            // вернуть параметры алгоритма
            return new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.STB.OID.stb11762_sign), null
            ); 
        }
        public override ASN1.ISO.AlgorithmIdentifier SignDataAlgorithm(IRand rand) 
        {
            // вернуть параметры алгоритма
            return new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.STB.OID.stb11762_sign), null
            ); 
        }
        public override ASN1.ISO.AlgorithmIdentifier TransportKeyAlgorithm(IRand rand) 
        { 
            // вернуть параметры алгоритма
            return new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.STB.OID.stb11762_bdh_keyTrans),
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
            public PKCS12(PBE.PBEParameters parameters, string sboxParams) 
                
                // сохранить переданные параметры
                : base(parameters) { culture = new STB1176(sboxParams); } 
            
            // национальные особенности
            protected override CAPI.Culture BaseCulture { get { return culture; }} 

            // параметры алгоритмов
            public override ASN1.ISO.AlgorithmIdentifier HMacAlgorithm(IRand rand)
            { 
                // вернуть параметры алгоритма
                return new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(ASN1.STB.OID.stb34101_hmac_hspec), 
                    new ASN1.ISO.AlgorithmIdentifier(
                        new ASN1.ObjectIdentifier(ASN1.STB.OID.stb11761_hash), 
                        ASN1.Null.Instance
                    )
                ); 
            }
        }
    }
}
