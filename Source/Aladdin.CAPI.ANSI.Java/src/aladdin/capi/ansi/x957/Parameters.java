package aladdin.capi.ansi.x957;
import java.security.spec.*; 
import java.math.*; 

///////////////////////////////////////////////////////////////////////////
// Параметры ключей DSA
///////////////////////////////////////////////////////////////////////////
public final class Parameters extends DSAParameterSpec implements IParameters
{
    private static final long serialVersionUID = 8856242726702354075L;
    
    // конструктор
    public Parameters(BigInteger p, BigInteger q, BigInteger g) { super(p, q, g); }
}
