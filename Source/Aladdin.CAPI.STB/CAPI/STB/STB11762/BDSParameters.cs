using System; 

///////////////////////////////////////////////////////////////////////
// Параметры подписи
///////////////////////////////////////////////////////////////////////
namespace Aladdin.CAPI.STB.STB11762
{
    [Serializable]
    public class BDSParameters : IBDSParameters
    {
        // конструктор
        public BDSParameters(int l, int r, Math.BigInteger p, 
            Math.BigInteger q, Math.BigInteger a, byte[] h, byte[] z)
        {
            // сохранить переданные параметры
            this.l = l; this.r = r; this.p = p; this.q = q; this.a = a; this.h = h; this.z = z;  
        }
        public BDSParameters(ASN1.STB.BDSParamsList list)
        {
            // получить параметры l и r
            l = list.BDSParameterL.Value.IntValue; 
            r = list.BDSParameterR.Value.IntValue; 

            // получить закодированные параметры P, Q, A
            p = list.BDSParameterP.Value; 
            q = list.BDSParameterQ.Value;
            a = list.BDSParameterA.Value;

            // получить закодированный параметр H
            h = list.BDSParameterH.Value;  
        
            // проверить наличие параметров генерации
            if (list.BDSParamInitData == null) z = null; 
            else {
                // получить параметры генерации
                z = list.BDSParamInitData.BDSPrmsInitZSequence.Value;
            }
        }
        public int              L { get { return l; }} private int		        l;
        public int              R { get { return r; }} private int		        r;
        public Math.BigInteger  P { get { return p; }} private Math.BigInteger  p;
        public Math.BigInteger  Q { get { return q; }} private Math.BigInteger  q;	
        public Math.BigInteger  G { get { return a; }} private Math.BigInteger  a;
        public byte[]           H { get { return h; }} private byte[]	        h;
        public byte[]           Z { get { return z; }} private byte[]	        z;
    }
}
