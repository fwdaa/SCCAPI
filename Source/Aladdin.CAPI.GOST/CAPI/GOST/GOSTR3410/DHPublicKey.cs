namespace Aladdin.CAPI.GOST.GOSTR3410
{
    ///////////////////////////////////////////////////////////////////////////
    // Открытый ключ алгоритма ГОСТ Р 34.10-1994
    ///////////////////////////////////////////////////////////////////////////
    public class DHPublicKey : CAPI.PublicKey, IDHPublicKey
    {
        // параметры ключа
        private IDHParameters parameters; private Math.BigInteger y;
    
        // конструктор
	    public DHPublicKey(CAPI.KeyFactory keyFactory, 
            IDHParameters parameters, Math.BigInteger y) : base(keyFactory)
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
