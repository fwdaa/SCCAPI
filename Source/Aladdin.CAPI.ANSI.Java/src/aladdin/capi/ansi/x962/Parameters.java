package aladdin.capi.ansi.x962;
import aladdin.asn1.iso.*;
import aladdin.capi.ec.*;
import java.security.spec.*;
import java.math.*;

////////////////////////////////////////////////////////////////////////////////
// Параметры ключа 
////////////////////////////////////////////////////////////////////////////////
public class Parameters extends ECParameterSpec implements aladdin.capi.ansi.x962.IParameters
{
    // выполнить преобразование типа
    public static Parameters convert(IParameters parameters)
    {
        // проверить тип параметров
        if (parameters instanceof Parameters) return (Parameters)parameters; 
        
        // выполнить преобразование типа
        return new Parameters(parameters.getCurve(), parameters.getGenerator(), 
            parameters.getOrder(), parameters.getCofactor(), parameters.getHash()
        ); 
    }
    // конструктор 
    public Parameters(Curve curve, ECPoint g, BigInteger n, int h, AlgorithmIdentifier hash)
    {
        // сохранить переданные параметры
        super(curve, g, n, h); this.hash = hash;
    }
    // эллиптическая кривая
    @Override public final Curve getCurve() { return (Curve)super.getCurve(); } 
    
    // алгоритм хэширования
	@Override public final AlgorithmIdentifier getHash () { return hash; } 
    // алгоритм хэширования
    private final AlgorithmIdentifier hash; 
}
