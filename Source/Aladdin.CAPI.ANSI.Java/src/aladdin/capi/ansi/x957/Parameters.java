package aladdin.capi.ansi.x957;
import java.security.spec.*; 
import java.math.*; 

///////////////////////////////////////////////////////////////////////////
// Параметры ключей DSA
///////////////////////////////////////////////////////////////////////////
public final class Parameters extends DSAParameterSpec implements IParameters
{
    // конструктор
    public Parameters(BigInteger p, BigInteger q, BigInteger g) { super(p, q, g); }
}
