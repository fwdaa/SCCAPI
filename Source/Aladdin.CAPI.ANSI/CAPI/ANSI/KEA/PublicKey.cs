namespace Aladdin.CAPI.ANSI.KEA
{
    ///////////////////////////////////////////////////////////////////////////
    // Открытый ключ алгоритма KEA
    ///////////////////////////////////////////////////////////////////////////
    public class PublicKey : CAPI.PublicKey, IPublicKey
    {
        // параметры ключа
        private CAPI.IParameters parameters; private Math.BigInteger y;
    
        // конструктор
	    public PublicKey(CAPI.KeyFactory keyFactory, 
            IParameters parameters, Math.BigInteger y) : base(keyFactory)
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
