///////////////////////////////////////////////////////////////////////
// Открытый ключ подписи и обмена
///////////////////////////////////////////////////////////////////////
namespace Aladdin.CAPI.STB.STB11762
{
    public class BDSBDHPublicKey : CAPI.PublicKey, IBDSBDHPublicKey
    {
        // параметры ключа
        private IBDSBDHParameters parameters; 
        // открытый ключ подписи и обмена
	    private Math.BigInteger bdsY; private Math.BigInteger bdhY;	
    
        // конструктор
	    public BDSBDHPublicKey(CAPI.KeyFactory keyFactory, IBDSBDHParameters parameters, 
            Math.BigInteger bdsY, Math.BigInteger bdhY) : base(keyFactory)
        {
            // сохранить переданные параметры
            this.parameters = parameters; this.bdsY = bdsY; this.bdhY = bdhY;
        }
        // параметры ключа
	    public override CAPI.IParameters Parameters { get { return parameters; }}
        // значение открытого ключа
	    Math.BigInteger IBDSPublicKey.Y { get { return bdsY; }}
	    Math.BigInteger IBDHPublicKey.Y { get { return bdhY; }}
    }
}
