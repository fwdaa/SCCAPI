package aladdin.capi.gost.gostr3410;
import aladdin.asn1.iso.*;
import aladdin.asn1.gost.*;
import java.security.spec.*; 
import java.math.*; 

///////////////////////////////////////////////////////////////////////////
// Параметры ГОСТ Р 34.10-1994
///////////////////////////////////////////////////////////////////////////
public class DHParameters extends DSAParameterSpec implements IDHParameters
{
/*    
    // выполнить преобразование типа
    public static DHParameters convert(IDHParameters parameters)
    {
        // проверить тип параметров
        if (parameters instanceof DHParameters) return (DHParameters)parameters; 
        
        // выполнить преобразование типа
        return new DHParameters(parameters.getP(), 
            parameters.getQ(), parameters.getG(), parameters.validationParameters()
        ); 
    }
*/
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
    
    // параметры проверки
    private final AlgorithmIdentifier validationParameters;   
}
