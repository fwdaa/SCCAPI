///////////////////////////////////////////////////////////////////////////
// Параметры алгоритма выработки/проверки подписи СТБ 1176.2
///////////////////////////////////////////////////////////////////////////
namespace Aladdin.CAPI.STB.STB11762
{
    public interface IBDSParameters : CAPI.IParameters
    {
	    int			    L { get; } // параметр L
	    int			    R { get; } // параметр R
	    Math.BigInteger	P { get; } // параметр P
	    Math.BigInteger	Q { get; } // параметр Q
	    Math.BigInteger	G { get; } // параметр A
	    byte[] 		    H { get; } // стартовое хэш-значение
        byte[]          Z { get; } // параметры генерации
    }
}
