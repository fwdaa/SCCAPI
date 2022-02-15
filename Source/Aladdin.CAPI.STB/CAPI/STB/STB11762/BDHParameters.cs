///////////////////////////////////////////////////////////////////////
// Параметры обмена
///////////////////////////////////////////////////////////////////////
namespace Aladdin.CAPI.STB.STB11762
{
    public class BDHParameters : IBDHParameters
    {
        // конструктор
        public BDHParameters(int l, int r, Math.BigInteger p, Math.BigInteger g, int n, byte[] z) 
        {
            // сохранить переданные параметры
            this.l = l; this.r = r; this.p = p; this.g = g; this.n = n; this.z = z; 
        }
        public BDHParameters(ASN1.STB.BDHParamsList list)
        {
            // получить параметры l, r и N
            l = list.BDHParameterL.Value.IntValue; 
            r = list.BDHParameterR.Value.IntValue; 
            n = list.BDHParameterN.Value.IntValue; 

            // получить закодированные параметры P, G
            p = list.BDHParameterP.Value; 
            g = list.BDHParameterG.Value;

            // проверить наличие параметров генерации
            if (list.BDHParamInitData == null) z = null; 
            else {
                // получить параметры генерации
                z = list.BDHParamInitData.BDHPrmsInitZSequence.Value;
            }
        }
        public int              L { get { return l; }} private int		        l;
        public int              R { get { return r; }} private int		        r;
        public Math.BigInteger  P { get { return p; }} private Math.BigInteger  p;
        public Math.BigInteger  G { get { return g; }} private Math.BigInteger  g;	
        public int              N { get { return n; }} private int              n;	
        public byte[]           Z { get { return z; }} private byte[]           z;	
    }
}
