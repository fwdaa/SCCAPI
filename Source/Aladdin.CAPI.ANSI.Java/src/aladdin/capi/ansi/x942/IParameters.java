package aladdin.capi.ansi.x942;
import java.math.*;

///////////////////////////////////////////////////////////////////////////
// Параметры ключей DH
///////////////////////////////////////////////////////////////////////////
public interface IParameters extends aladdin.capi.IParameters
{
    BigInteger getP(); // параметр P
    BigInteger getQ(); // параметр Q
    BigInteger getG(); // параметр G
}
