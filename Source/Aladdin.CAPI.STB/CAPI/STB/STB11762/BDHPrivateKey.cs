using System;
using System.Diagnostics.CodeAnalysis;

///////////////////////////////////////////////////////////////////////////
// Личный ключ алгоритма СТБ 1176.2
///////////////////////////////////////////////////////////////////////////
namespace Aladdin.CAPI.STB.STB11762
{
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
    public class BDHPrivateKey : CAPI.PrivateKey, IBDHPrivateKey
    {
        // параметры ключа и секретное значение
        private IBDHParameters parameters; private Math.BigInteger x;
    
        // конструктор
	    public BDHPrivateKey(CAPI.Factory factory, SecurityObject scope, string keyOID, 
            IBDHParameters parameters, Math.BigInteger x) : base(factory, scope, keyOID)
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
