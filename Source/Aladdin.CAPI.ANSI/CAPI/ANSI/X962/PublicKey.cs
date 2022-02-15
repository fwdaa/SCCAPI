using System; 

namespace Aladdin.CAPI.ANSI.X962
{
    ///////////////////////////////////////////////////////////////////////////
    // Открытый ключ алгоритма 
    ///////////////////////////////////////////////////////////////////////////
    public class PublicKey : CAPI.PublicKey, IPublicKey
    {
        // параметры ключа
        private IParameters parameters; private EC.Point q;
    
        // конструктор
	    public PublicKey(CAPI.KeyFactory keyFactory, 
            IParameters parameters, EC.Point q) : base(keyFactory)
        {
            // сохранить переданные параметры
            this.parameters = parameters; this.q = q; 
        }
        // параметры ключа
	    public override CAPI.IParameters Parameters { get { return parameters; }}
        // точка эллиптической кривой
        public virtual EC.Point Q { get { return q; }}
    }
}
