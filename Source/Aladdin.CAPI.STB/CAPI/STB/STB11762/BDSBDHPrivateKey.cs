using System;
using System.Diagnostics.CodeAnalysis;

///////////////////////////////////////////////////////////////////////
// Личный ключ подписи и обмена
///////////////////////////////////////////////////////////////////////
namespace Aladdin.CAPI.STB.STB11762
{
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
    public class BDSBDHPrivateKey : CAPI.PrivateKey, IBDSBDHPrivateKey
    {
        // параметры ключа 
        private IBDSBDHParameters parameters; 
        // секретные значения
        private Math.BigInteger bdsX; private Math.BigInteger bdhX;
    
        // конструктор
	    public BDSBDHPrivateKey(CAPI.Factory factory, SecurityObject scope, 
            string keyOID, IBDSBDHParameters parameters, Math.BigInteger bdsX, 
            Math.BigInteger bdhX) : base(factory, scope, keyOID)
	    { 	
            // сохранить переданные параметры
		    this.parameters = parameters; this.bdsX = bdsX; this.bdhX = bdhX;
        } 
        // параметры ключа
	    public override CAPI.IParameters Parameters { get { return parameters; }}
        // секретные значения
	    Math.BigInteger IBDSPrivateKey.X { get { return bdsX; }}
	    Math.BigInteger IBDHPrivateKey.X { get { return bdhX; }}
    }
}
