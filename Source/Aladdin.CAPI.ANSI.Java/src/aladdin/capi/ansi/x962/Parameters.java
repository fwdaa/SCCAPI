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
    private static final long serialVersionUID = 3811184664225753306L;
    
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
    public static IParameters getInstance(AlgorithmParameterSpec paramSpec) 
        throws InvalidParameterSpecException
    { 
        // выполнить преобразование типа
        if (paramSpec instanceof IParameters) return (IParameters)paramSpec; 
            
        // в зависимости от типа данных
        if (paramSpec instanceof ECParameterSpec)
        {
            // выполнить преобразование типа
            ECParameterSpec ecParamSpec = (ECParameterSpec)paramSpec; 
            
            // преобразовать тип кривой
            aladdin.capi.ec.Curve curve = aladdin.capi.ec.Curve.convert(
                ecParamSpec.getCurve()
            );
            // создать параметры ключа
            return new Parameters(curve, ecParamSpec.getGenerator(), 
                ecParamSpec.getOrder(), ecParamSpec.getCofactor(), null
            ); 
        }
        // тип параметров не поддерживается
        throw new InvalidParameterSpecException(); 
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

    @SuppressWarnings({"unchecked"}) 
    @Override public <T extends AlgorithmParameterSpec> 
        T getParameterSpec(Class<T> specType) 
            throws InvalidParameterSpecException
    {
        // вернуть параметры
        if (specType.isAssignableFrom(IParameters.class)) return (T)this; 
        
        // вернуть параметры
        if (specType.isAssignableFrom(ECParameterSpec.class)) return (T)this; 
        
        // тип параметров не поддерживается
        throw new InvalidParameterSpecException(); 
    }
}
