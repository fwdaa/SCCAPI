using System;
using System.Diagnostics.CodeAnalysis;

namespace Aladdin.CAPI.GOST.GOSTR3410
{
    ///////////////////////////////////////////////////////////////////////////
    // Личный ключ алгоритма ГОСТ Р 34.10-1994
    ///////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
    public class DHPrivateKey : CAPI.PrivateKey, IDHPrivateKey
    {
        // параметры ключа и секретное значение
        private IDHParameters parameters; private Math.BigInteger x;
    
        // конструктор
	    public DHPrivateKey(CAPI.Factory factory, SecurityObject scope, string keyOID, 
            IDHParameters parameters, Math.BigInteger x) : base(factory, scope, keyOID)
	    { 	
            // сохранить переданные параметры
		    this.parameters = parameters; this.x = x; 
        } 
        // параметры ключа
	    public override CAPI.IParameters Parameters { get { return parameters; }}
        // секретное значение
	    public virtual Math.BigInteger X { get { return x; }}
    }
}
