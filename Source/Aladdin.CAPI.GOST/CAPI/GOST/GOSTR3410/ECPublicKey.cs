///////////////////////////////////////////////////////////////////////////
// Открытый ключ алгоритма ГОСТ Р 34.10-2001,2012
///////////////////////////////////////////////////////////////////////////
namespace Aladdin.CAPI.GOST.GOSTR3410
{
    public class ECPublicKey : CAPI.PublicKey, IECPublicKey
    {
        // параметры ключа
        private IECParameters parameters; private EC.Point q;
    
        // конструктор
	    public ECPublicKey(CAPI.KeyFactory keyFactory, 
            IECParameters parameters, EC.Point q) : base(keyFactory)
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
