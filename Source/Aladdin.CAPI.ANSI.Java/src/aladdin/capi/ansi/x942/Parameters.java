package aladdin.capi.ansi.x942;
import javax.crypto.spec.*; 
import java.math.*; 

///////////////////////////////////////////////////////////////////////////
// Параметры ключей DH
///////////////////////////////////////////////////////////////////////////
public final class Parameters extends DHParameterSpec implements IParameters 
{
    // параметр Q
    private final BigInteger q;
    
    // конструктор
    public Parameters(BigInteger p, BigInteger q, BigInteger g) 
    { 
        // сохранить переданные параметры
        super(p, g); this.q = q; 
    }
    // параметр Q
    @Override public final BigInteger getQ() { return q; } 
}
