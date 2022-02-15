using System;
using System.Diagnostics.CodeAnalysis;

///////////////////////////////////////////////////////////////////////////
// Личный ключ алгоритма СТБ 1176.2
///////////////////////////////////////////////////////////////////////////
namespace Aladdin.CAPI.STB.STB11762
{
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
    public class BDSPrivateKey : CAPI.PrivateKey, IBDSPrivateKey
    {
        // параметры ключа и секретное значение
        private IBDSParameters parameters; private Math.BigInteger x;
    
        // конструктор
	    public BDSPrivateKey(CAPI.Factory factory, SecurityObject scope, string keyOID, 
            IBDSParameters parameters, Math.BigInteger x) : base(factory, scope, keyOID)
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
