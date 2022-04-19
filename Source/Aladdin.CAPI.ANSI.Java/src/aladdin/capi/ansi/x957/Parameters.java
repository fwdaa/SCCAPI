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
    public static IParameters getInstance(AlgorithmParameterSpec paramSpec) 
        throws InvalidParameterSpecException
    { 
        // выполнить преобразование типа
        if (paramSpec instanceof IParameters) return (IParameters)paramSpec; 
            
        // в зависимости от типа данных
        if (paramSpec instanceof DSAParameterSpec)
        {
            // выполнить преобразование типа
            DSAParameterSpec dsaParamSpec = (DSAParameterSpec)paramSpec; 
            
            // создать параметры ключа
            return new Parameters(
                dsaParamSpec.getP(), dsaParamSpec.getQ(), dsaParamSpec.getG()
            ); 
        }
        // тип параметров не поддерживается
        throw new InvalidParameterSpecException(); 
    }
    // конструктор
    public Parameters(BigInteger p, BigInteger q, BigInteger g) { super(p, q, g); }

    @SuppressWarnings({"unchecked"}) 
    @Override public <T extends AlgorithmParameterSpec> 
        T getParameterSpec(Class<T> specType) 
            throws InvalidParameterSpecException
    {
        // вернуть параметры
        if (specType.isAssignableFrom(IParameters.class)) return (T)this; 
        
        // вернуть параметры
        if (specType.isAssignableFrom(DSAParameterSpec.class)) return (T)this; 
        
        // тип параметров не поддерживается
        throw new InvalidParameterSpecException(); 
    }
}
