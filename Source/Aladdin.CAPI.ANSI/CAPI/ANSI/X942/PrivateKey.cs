using System;
using System.Diagnostics.CodeAnalysis;

namespace Aladdin.CAPI.ANSI.X942
{
	///////////////////////////////////////////////////////////////////////////
	// Личный ключ алгоритма DH
	///////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
	public class PrivateKey : CAPI.PrivateKey, IPrivateKey
	{
        // параметры ключа и секретное значение
        private IParameters parameters; private Math.BigInteger x;
    
        // конструктор
	    public PrivateKey(CAPI.Factory factory, SecurityObject scope, string keyOID, 
            IParameters parameters, Math.BigInteger x) : base(factory, scope, keyOID)
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
