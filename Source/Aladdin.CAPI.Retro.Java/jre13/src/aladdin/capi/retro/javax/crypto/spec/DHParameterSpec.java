package aladdin.capi.retro.javax.crypto.spec;
import java.math.*;
import java.security.spec.*;

///////////////////////////////////////////////////////////////////////////////
// Параметры алгоритма DH
///////////////////////////////////////////////////////////////////////////////
public class DHParameterSpec implements AlgorithmParameterSpec 
{
    private final BigInteger p; // параметр P
    private final BigInteger g; // параметр G
    private final int l;        // размер генерируемого ключа в битах

    // конструктор
    public DHParameterSpec(BigInteger p, BigInteger g, int l) 
    {
        // сохранить переданные параметры
        this.p = p; this.g = g; this.l = l; 
    }
    public DHParameterSpec(BigInteger p, BigInteger g) { this(p, g, 0); }
    
    // параметры алгоритма
    public BigInteger getP() { return p; } // параметр P
    public BigInteger getG() { return g; } // параметр G
    public int        getL() { return l; } // размер генерируемого ключа в битах
}
