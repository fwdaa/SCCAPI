package aladdin.capi.ansi.kea;
import java.math.*; 

///////////////////////////////////////////////////////////////////////////
// Параметры ключей KEA
///////////////////////////////////////////////////////////////////////////
public interface IParameters extends aladdin.capi.IParameters 
{
    BigInteger getP(); // параметр P
    BigInteger getQ(); // параметр Q
    BigInteger getG(); // параметр G
}
