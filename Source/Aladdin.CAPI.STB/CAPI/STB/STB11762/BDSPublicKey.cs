///////////////////////////////////////////////////////////////////////////
// Открытый ключ алгоритма СТБ 1176.2
///////////////////////////////////////////////////////////////////////////
namespace Aladdin.CAPI.STB.STB11762
{
    public class BDSPublicKey : CAPI.PublicKey, IBDSPublicKey
    {
        // параметры ключа
        private IBDSParameters parameters; private Math.BigInteger y;
    
        // конструктор
	    public BDSPublicKey(CAPI.KeyFactory keyFactory, 
            IBDSParameters parameters, Math.BigInteger y) : base(keyFactory)
        {
            // сохранить переданные параметры
            this.parameters = parameters; this.y = y; 
        }
        // параметры ключа
	    public override CAPI.IParameters Parameters { get { return parameters; }}
        // значение открытого ключа
        public virtual Math.BigInteger Y { get { return y; }}
    }
}
