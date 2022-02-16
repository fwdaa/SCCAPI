///////////////////////////////////////////////////////////////////////////
// Личный ключ алгоритма ГОСТ Р 34.10-2001,2012
///////////////////////////////////////////////////////////////////////////
namespace Aladdin.CAPI.GOST.GOSTR3410
{
    public interface IECPrivateKey : CAPI.IPrivateKey 
    {
	    Math.BigInteger D { get; } // координата X точки 
    }
}