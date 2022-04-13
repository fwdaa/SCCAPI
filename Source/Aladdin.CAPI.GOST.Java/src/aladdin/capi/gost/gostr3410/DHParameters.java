package aladdin.capi.gost.gostr3410;
import aladdin.asn1.iso.*;
import aladdin.asn1.gost.*;
import java.security.spec.*; 
import java.math.*; 
import javax.crypto.spec.*;

///////////////////////////////////////////////////////////////////////////
// Параметры ГОСТ Р 34.10-1994
///////////////////////////////////////////////////////////////////////////
public class DHParameters extends DSAParameterSpec implements IDHParameters
{
    private static final long serialVersionUID = -7173437093791632739L;
    
    // конструктор
    public static IDHParameters getInstance(AlgorithmParameterSpec paramSpec) 
        throws InvalidParameterSpecException
    { 
        // проверить требуемый тип данных
        if (paramSpec instanceof DSAParameterSpec)
        {
            // выполнить преобразование типа
            if (paramSpec instanceof IDHParameters) return (IDHParameters)paramSpec; 
            
            // выполнить преобразование типа
            DSAParameterSpec dsaParamSpec = (DSAParameterSpec)paramSpec; 
            
            // создать параметры ключа
            return new DHParameters(dsaParamSpec.getP(), 
                dsaParamSpec.getQ(), dsaParamSpec.getG(), null
            ); 
        }
        // тип параметров не поддерживается 
        throw new InvalidParameterSpecException(); 
    }
    // параметры проверки
    private final AlgorithmIdentifier validationParameters;   

    // конструктор 
    public DHParameters(BigInteger p, BigInteger q, BigInteger a, 
        AlgorithmIdentifier validationParameters)
    {
        // сохранить переданные параметры
        super(p, q, a); this.validationParameters = validationParameters;
    }
    // конструктор 
    public DHParameters(GOSTR3410ParamSet1994 parameters) 
    {
        // сохранить переданные параметры
        super(parameters.p().value(), parameters.q().value(), parameters.a().value()); 
        
        // сохранить переданные параметры
        this.validationParameters = parameters.validationAlgorithm(); 
    }
    @Override public AlgorithmIdentifier validationParameters() { return validationParameters; }
    
    @SuppressWarnings({"unchecked"}) 
    @Override public <T extends AlgorithmParameterSpec> 
        T getParameterSpec(Class<T> specType) 
            throws InvalidParameterSpecException
    {
        // вернуть параметры 
        if (specType.isAssignableFrom(DSAParameterSpec.class)) return (T)this; 
        
        // в зависимости от типа данных
        if (specType.isAssignableFrom(DHParameterSpec.class))
        {
            // вернуть параметры алгоритма
            return (T)new DHParameterSpec(getP(), getG()); 
        }
        // тип параметров не поддерживается 
        throw new InvalidParameterSpecException(); 
    }
}
