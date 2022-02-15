using System; 

namespace Aladdin.CAPI.ANSI.X962
{
    ////////////////////////////////////////////////////////////////////////////////
    // Параметры ключа 
    ////////////////////////////////////////////////////////////////////////////////
    public interface IParameters : CAPI.IParameters
    {
        EC.Curve                Curve     { get; } // эллиптическая кривая
        EC.Point                        Generator { get; } // базовая точка G
        Math.BigInteger                 Order     { get; } // порядок базовой точки
        Math.BigInteger                 Cofactor  { get; } // сомножитель
        ASN1.ISO.AlgorithmIdentifier    Hash      { get; } // алгоритм хэширования
    }
}
