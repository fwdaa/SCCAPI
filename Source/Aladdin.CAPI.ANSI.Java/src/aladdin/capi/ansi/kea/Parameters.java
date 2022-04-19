package aladdin.capi.ansi.kea;
import java.math.*; 
import java.security.spec.*;
import javax.crypto.spec.*; 

///////////////////////////////////////////////////////////////////////////
// Параметры ключей KEA
///////////////////////////////////////////////////////////////////////////
public final class Parameters extends DHParameterSpec implements IParameters 
{
    private static final long serialVersionUID = 6480493715555195269L;
    
    // конструктор
    public static IParameters getInstance(AlgorithmParameterSpec paramSpec) 
        throws InvalidParameterSpecException
    { 
        // выполнить преобразование типа
        if (paramSpec instanceof IParameters) return (IParameters)paramSpec; 
        
        // тип параметров не поддерживается
        throw new InvalidParameterSpecException(); 
    }
    // конструктор
    public Parameters(BigInteger p, BigInteger q, BigInteger g)
    {
        // сохранить переданные параметры
        super(p, g); this.q = q; 
    }
    // параметры ключей 
	@Override public final BigInteger getQ() { return q;  } private final BigInteger q;

    @SuppressWarnings({"unchecked"}) 
    @Override public <T extends AlgorithmParameterSpec> 
        T getParameterSpec(Class<T> specType) 
            throws InvalidParameterSpecException
    {
        // вернуть параметры
        if (specType.isAssignableFrom(IParameters.class)) return (T)this; 
        
        // вернуть параметры
        if (specType.isAssignableFrom(DHParameterSpec.class)) return (T)this; 
        
        // тип параметров не поддерживается
        throw new InvalidParameterSpecException(); 
    }
}
