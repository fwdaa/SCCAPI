using System;
using System.Diagnostics.CodeAnalysis;

namespace Aladdin.CAPI.GOST.GOSTR3410
{
    ///////////////////////////////////////////////////////////////////////////
    // Личный ключ алгоритма ГОСТ Р 34.10-2001,2012
    ///////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
    public class ECPrivateKey : CAPI.PrivateKey, IECPrivateKey
    {
        // параметры ключа и секретное значение
        private IECParameters parameters; private Math.BigInteger d;
    
        // конструктор
	    public ECPrivateKey(CAPI.Factory factory, SecurityObject scope, string keyOID, 
            IECParameters parameters, Math.BigInteger d) : base(factory, scope, keyOID)
	    { 	
            // сохранить переданные параметры
		    this.parameters = parameters; this.d = d; 
        } 
        // параметры ключа
	    public override CAPI.IParameters Parameters { get { return parameters; }}
        // секретное значение
	    public virtual Math.BigInteger D { get { return d; }}
    }
}