package aladdin.capi.gost.gostr3410;
import aladdin.asn1.gost.*; 
import aladdin.capi.ec.*; 
import java.security.spec.*; 
import java.math.*; 

///////////////////////////////////////////////////////////////////////////
// Параметры эллиптических кривых
///////////////////////////////////////////////////////////////////////////
public class ECParameters extends ECParameterSpec implements IECParameters
{
    private static final long serialVersionUID = 5455381783925257879L;
    
    // выполнить преобразование типа
    public static ECParameters convert(IECParameters parameters)
    {
        // проверить тип параметров
        if (parameters instanceof ECParameters) return (ECParameters)parameters; 
        
        // выполнить преобразование типа
        return new ECParameters(parameters.getCurve(), 
            parameters.getGenerator(), parameters.getOrder()
        ); 
    }
    // конструктор
    public static IECParameters getInstance(AlgorithmParameterSpec paramSpec) 
        throws InvalidParameterSpecException
    { 
        // выполнить преобразование типа
        if (paramSpec instanceof IECParameters) return (IECParameters)paramSpec; 
            
        // в зависимости от типа данных
        if (paramSpec instanceof ECParameterSpec)
        {
            // выполнить преобразование типа
            ECParameterSpec ecParamSpec = (ECParameterSpec)paramSpec; 
        
            // проверить корректность параметров
            if (ecParamSpec.getCofactor() != 1) throw new InvalidParameterSpecException(); 
            try { 
                // преобразовать тип кривой
                CurveFp curve = CurveFp.convert(ecParamSpec.getCurve());
        
                // создать параметры ключа
                return new ECParameters(curve, ecParamSpec.getGenerator(), ecParamSpec.getOrder()); 
            }
            // при возникновении ошибки
            catch (IllegalArgumentException e) 
            { 
                // изменить тип исключения
                throw new InvalidParameterSpecException(e.getMessage()); 
            }
        }
        // тип параметров не поддерживается 
        throw new InvalidParameterSpecException(); 
    }
    // конструктор 
    public ECParameters(GOSTR3410ParamSet parameters) 
    {
        // сохранить переданные параметры
        this(new CurveFp(parameters.p().value(), 
            parameters.a().value(), parameters.b().value(), null
            ), new ECPoint(parameters.x().value(), parameters.y().value()
            ), parameters.q().value()
        ); 
    }
    // конструктор 
    public ECParameters(CurveFp curve, ECPoint p, BigInteger q)
    {
        // сохранить переданные параметры
        super(curve, p, q, 1); 
    }
    // эллиптическая кривая
    @Override public final CurveFp getCurve() { return (CurveFp)super.getCurve(); } 
    
    @SuppressWarnings({"unchecked"}) 
    @Override public <T extends AlgorithmParameterSpec> 
        T getParameterSpec(Class<T> specType) 
            throws InvalidParameterSpecException
    {
        // вернуть параметры
        if (specType.isAssignableFrom(IECParameters.class)) return (T)this; 
        
        // вернуть параметры
        if (specType.isAssignableFrom(ECParameterSpec.class)) return (T)this; 
        
        // тип параметров не поддерживается 
        throw new InvalidParameterSpecException(); 
    }
}
