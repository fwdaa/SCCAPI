///////////////////////////////////////////////////////////////////////////
// Открытый ключ алгоритма СТБ 34.101
///////////////////////////////////////////////////////////////////////////
namespace Aladdin.CAPI.STB.STB34101
{
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
        // значение открытого ключа
        public virtual EC.Point Q { get { return q; }}
    }
}
