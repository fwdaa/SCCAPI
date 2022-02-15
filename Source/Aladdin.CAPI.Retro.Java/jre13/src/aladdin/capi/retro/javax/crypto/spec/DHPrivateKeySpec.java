package aladdin.capi.retro.javax.crypto.spec;
import java.security.spec.*;
import java.math.*;

///////////////////////////////////////////////////////////////////////////////
// Личный ключ алгоритма DH
///////////////////////////////////////////////////////////////////////////////
public class DHPrivateKeySpec implements KeySpec 
{
    private final BigInteger x; // параметр X
    private final BigInteger p; // параметр P
    private final BigInteger g; // параметр G

    // конструктор
    public DHPrivateKeySpec(BigInteger x, BigInteger p, BigInteger g) 
    {
        // сохранить переданные параметры
        this.x = x; this.p = p; this.g = g; 
    }
    public BigInteger getX() { return x; }
    public BigInteger getP() { return p; }
    public BigInteger getG() { return g; }
}
