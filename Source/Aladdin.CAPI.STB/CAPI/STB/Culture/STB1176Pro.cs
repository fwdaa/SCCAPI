﻿namespace Aladdin.CAPI.STB.Culture
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
        public new class PKCS12 : PBE.PBEDefaultCulture
        {
            // конструктор
            public PKCS12(PBE.PBEParameters parameters, string sboxParams) 
                
                // сохранить переданные параметры
                : base(new STB1176Pro(sboxParams), parameters, true) {} 
        }
    }
}
