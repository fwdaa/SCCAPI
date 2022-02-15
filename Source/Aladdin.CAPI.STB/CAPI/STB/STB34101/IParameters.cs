////////////////////////////////////////////////////////////////////////////////
// Параметры ключа СТБ 34.101
////////////////////////////////////////////////////////////////////////////////
namespace Aladdin.CAPI.STB.STB34101
{
    public interface IParameters : CAPI.IParameters
    {
        EC.CurveFp      Curve     { get; } // эллиптическая кривая
        EC.Point        Generator { get; } // базовая точка G
        Math.BigInteger Order     { get; } // порядок базовой точки
    }
}
