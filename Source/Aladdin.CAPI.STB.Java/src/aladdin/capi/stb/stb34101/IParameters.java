package aladdin.capi.stb.stb34101;
import aladdin.capi.ec.*; 
import java.security.spec.*; 
import java.math.*; 

////////////////////////////////////////////////////////////////////////////////
// Параметры ключа СТБ 34.101
////////////////////////////////////////////////////////////////////////////////
public interface IParameters extends aladdin.capi.IParameters
{
    CurveFp     getCurve    (); // эллиптическая кривая
    ECPoint     getGenerator(); // базовая точка G
    BigInteger  getOrder    (); // порядок базовой точки
}
