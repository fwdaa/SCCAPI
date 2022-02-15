package aladdin.capi.retro.javax.crypto.spec;
import java.math.*;
import java.security.spec.*;

///////////////////////////////////////////////////////////////////////////////
// Открытый ключ алгоритма DH
///////////////////////////////////////////////////////////////////////////////
public class DHPublicKeySpec implements KeySpec 
{
    private final BigInteger y; // параметр Y
    private final BigInteger p; // параметр P
    private final BigInteger g; // параметр G

    // конструктор
    public DHPublicKeySpec(BigInteger y, BigInteger p, BigInteger g) 
    {
        // сохранить переданные параметры
        this.y = y; this.p = p; this.g = g; 
    }
    public BigInteger getY() { return y; }
    public BigInteger getP() { return p; }
    public BigInteger getG() { return g; }
}
