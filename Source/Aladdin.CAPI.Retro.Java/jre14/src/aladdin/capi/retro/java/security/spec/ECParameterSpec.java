package aladdin.capi.retro.java.security.spec;
import java.security.spec.*; 
import java.math.*;

///////////////////////////////////////////////////////////////////////////////
// Параметры алгоритма на эллиптических кривых
///////////////////////////////////////////////////////////////////////////////
public class ECParameterSpec implements AlgorithmParameterSpec 
{
    private final EllipticCurve curve;  // эллиптическая кривая
    private final ECPoint       g;      // базовая точка эллиптической кривой 
    private final BigInteger     n;      // порядок базовой точки
    private final int            h;      // сомножитель

    // конструктор
    public ECParameterSpec(EllipticCurve curve, ECPoint g, BigInteger n, int h) 
    {
        // проверить наличие параметров
        if (curve == null) throw new NullPointerException("curve is null");
        if (g     == null) throw new NullPointerException("g is null"    );
        if (n     == null) throw new NullPointerException("n is null"    );
        
        // проверить корректность параметров 
        if (n.signum() != 1) throw new IllegalArgumentException("n is not positive");
        if (h          <= 0) throw new IllegalArgumentException("h is not positive");
        
        // сохранить переданные параметры
        this.curve = curve; this.g = g; this.n = n; this.h = h;
    }
    public EllipticCurve getCurve    () { return curve; } // эллиптическая кривая
    public ECPoint       getGenerator() { return g;     } // базовая точка эллиптической кривой 
    public BigInteger     getOrder    () { return n;     } // порядок базовой точки
    public int            getCofactor () { return h;     } // сомножитель
}
