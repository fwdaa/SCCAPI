///////////////////////////////////////////////////////////////////////////
// Личный ключ алгоритма СТБ 1176.2
///////////////////////////////////////////////////////////////////////////
namespace Aladdin.CAPI.STB.STB11762
{
    public interface IBDSPrivateKey : CAPI.IPrivateKey 
    {
	    Math.BigInteger X { get; } // параметр X
    }
}
