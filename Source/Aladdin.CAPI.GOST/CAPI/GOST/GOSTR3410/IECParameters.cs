///////////////////////////////////////////////////////////////////////////
// Параметры эллиптических кривых
///////////////////////////////////////////////////////////////////////////
namespace Aladdin.CAPI.GOST.GOSTR3410
{
    public interface IECParameters : CAPI.IParameters
    {
        EC.CurveFp      Curve     { get; }     // эллиптическая кривая
	    EC.Point	    Generator { get; }     // базовая точка P
	    Math.BigInteger	Order     { get; }     // порядок базовой точки
    }
}