namespace Aladdin.CAPI.STB.Culture
{
    ///////////////////////////////////////////////////////////////////////////
    // Национальные особенности STB34101 (256 бит)
    ///////////////////////////////////////////////////////////////////////////
    public class STB34101_256 : STB34101
    {
        // параметры алгоритмов
        public override ASN1.ISO.AlgorithmIdentifier CipherAlgorithm(IRand rand) 
        { 
		    // сгенерировать синхропосылку
		    byte[] iv = new byte[16]; rand.Generate(iv, 0, iv.Length);

            // вернуть параметры алгоритма
            return new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.STB.OID.stb34101_belt_cfb_128),
                new ASN1.OctetString(iv)
            ); 
        }
        public override ASN1.ISO.AlgorithmIdentifier KeyWrapAlgorithm(IRand rand) 
        { 
            // вернуть параметры алгоритма
            return new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.STB.OID.stb34101_belt_keyWrap_128),
                ASN1.Null.Instance
            ); 
        }
        ///////////////////////////////////////////////////////////////////////////
        // Парольная защита
        ///////////////////////////////////////////////////////////////////////////
        public class PKCS12 : PBE.PBEDefaultCulture
        {
            // конструктор
            public PKCS12(PBE.PBEParameters parameters) 
                
                // сохранить переданные параметры
                : base(new STB34101_256(), parameters, true) {} 
        }
    }
}
