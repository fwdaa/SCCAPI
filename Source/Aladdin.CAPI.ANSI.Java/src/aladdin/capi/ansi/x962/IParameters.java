package aladdin.capi.ansi.x962;
import aladdin.capi.ec.*;
import aladdin.asn1.iso.*; 
import java.security.spec.*; 
import java.math.*; 

////////////////////////////////////////////////////////////////////////////////
// Параметры ключа 
////////////////////////////////////////////////////////////////////////////////
public interface IParameters extends aladdin.capi.IParameters
{
    Curve               getCurve    (); // эллиптическая кривая
    ECPoint             getGenerator(); // базовая точка G
    BigInteger          getOrder    (); // порядок базовой точки
    int                 getCofactor (); // #E(Fq)/n
    AlgorithmIdentifier getHash     (); // алгоритм хэширования
}
