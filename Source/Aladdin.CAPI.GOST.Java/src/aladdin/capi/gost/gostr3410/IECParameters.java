package aladdin.capi.gost.gostr3410;
import aladdin.capi.ec.*; 
import java.security.spec.*; 
import java.math.*; 

///////////////////////////////////////////////////////////////////////////
// Параметры эллиптических кривых
///////////////////////////////////////////////////////////////////////////
public interface IECParameters extends aladdin.capi.IParameters
{
    CurveFp     getCurve    (); // эллиптическая кривая
    ECPoint     getGenerator(); // базовая точка G
    BigInteger  getOrder    (); // порядок базовой точки
}
