///////////////////////////////////////////////////////////////////////////
// Параметры алгоритма выработки общего ключа СТБ 1176.2
///////////////////////////////////////////////////////////////////////////
namespace Aladdin.CAPI.STB.STB11762
{
    public interface IBDHParameters : CAPI.IParameters
    {
	    int			    L { get; } // параметр L
	    int			    R { get; } // параметр R
	    Math.BigInteger	P { get; } // параметр P
	    Math.BigInteger	G { get; } // параметр G
	    int			    N { get; } // параметр R
        byte[]          Z { get; } // параметры генерации
    }
}
