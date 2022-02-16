///////////////////////////////////////////////////////////////////////////
// Открытый ключ алгоритма СТБ 34.101
///////////////////////////////////////////////////////////////////////////
namespace Aladdin.CAPI.STB.STB34101
{
    public interface IPublicKey : CAPI.IPublicKey 
    {
	    EC.Point Q { get; } // точка эллиптической кривой
    }
}