using System;
using System.Diagnostics.CodeAnalysis;

///////////////////////////////////////////////////////////////////////////
// Личный ключ алгоритма СТБ 34.101
///////////////////////////////////////////////////////////////////////////
namespace Aladdin.CAPI.STB.STB34101
{
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
    public class PrivateKey : CAPI.PrivateKey, IPrivateKey
    {
        // параметры ключа и секретное значение
        private IParameters parameters; private Math.BigInteger d;
    
        // конструктор
	    public PrivateKey(CAPI.Factory factory, SecurityObject scope, string keyOID, 
            IParameters parameters, Math.BigInteger d) : base(factory, scope, keyOID)
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
