namespace Aladdin.CAPI.STB.Culture
{
    ///////////////////////////////////////////////////////////////////////////
    // Национальные особенности
    ///////////////////////////////////////////////////////////////////////////
    public class STB1176Pro : STB1176
    {
        // конструктор
        public STB1176Pro(string sboxParams) : base(sboxParams) {}
        // конструктор
        public STB1176Pro() : base() {}

        public override ASN1.ISO.AlgorithmIdentifier SignDataAlgorithm(IRand rand) 
        {
            // вернуть параметры алгоритма
            return new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.STB.OID.stb11762_pre_sign), null
            ); 
        }
        ///////////////////////////////////////////////////////////////////////////
        // Парольная защита
        ///////////////////////////////////////////////////////////////////////////
        public new class PKCS12 : PBE.PBECulture
        {
            // национальные особенности
            private CAPI.Culture culture; 

            // конструктор
            public PKCS12(PBE.PBEParameters parameters, string sboxParams) 
                
                // сохранить переданные параметры
                : base(parameters) { culture = new STB1176Pro(sboxParams); } 
            
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
