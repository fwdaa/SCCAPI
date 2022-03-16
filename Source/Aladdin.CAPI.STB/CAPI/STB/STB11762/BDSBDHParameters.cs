using System; 

///////////////////////////////////////////////////////////////////////
// Параметры подписи с параметрами обмена
///////////////////////////////////////////////////////////////////////
namespace Aladdin.CAPI.STB.STB11762
{
    [Serializable]
    public class BDSBDHParameters : IBDSBDHParameters
    {
        public BDSBDHParameters(IBDSParameters bdsParameters, IBDHParameters bdhParameters)
        {
            // сохранить переданные параметры
            this.bdsParameters = bdsParameters; this.bdhParameters = bdhParameters; 
        }
        public BDSBDHParameters(ASN1.STB.BDSBDHParamsList list)

            // сохранить переданные параметры
            : this(new BDSParameters(list.BDSParamsList), new BDHParameters(list.BDHParamsList)) {} 

        int              IBDSParameters.L { get { return bdsParameters.L; }}
        int              IBDSParameters.R { get { return bdsParameters.R; }}
        Math.BigInteger  IBDSParameters.P { get { return bdsParameters.P; }}
        Math.BigInteger  IBDSParameters.Q { get { return bdsParameters.Q; }}
        Math.BigInteger  IBDSParameters.G { get { return bdsParameters.G; }} 
        byte[]           IBDSParameters.H { get { return bdsParameters.H; }} 
        byte[]           IBDSParameters.Z { get { return bdsParameters.Z; }} 
    
        int              IBDHParameters.L { get { return bdhParameters.L; }}
        int              IBDHParameters.R { get { return bdhParameters.R; }}
        Math.BigInteger  IBDHParameters.P { get { return bdhParameters.P; }}
        Math.BigInteger  IBDHParameters.G { get { return bdhParameters.G; }}
        int              IBDHParameters.N { get { return bdhParameters.N; }} 
        byte[]           IBDHParameters.Z { get { return bdhParameters.Z; }} 

        private IBDSParameters	bdsParameters;		// параметры подписи 
        private IBDHParameters	bdhParameters;		// параметры обмена
    }
}
