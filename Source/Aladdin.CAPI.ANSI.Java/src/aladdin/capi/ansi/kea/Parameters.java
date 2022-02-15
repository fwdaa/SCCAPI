package aladdin.capi.ansi.kea;
import javax.crypto.spec.*; 
import java.math.*; 

///////////////////////////////////////////////////////////////////////////
// Параметры ключей KEA
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
    // параметры ключей 
	@Override public final BigInteger getQ() { return q;  } 
}
