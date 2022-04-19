package aladdin.capi.stb.stb34101;
import aladdin.capi.ec.*; 
import java.security.spec.*; 
import java.math.*;

////////////////////////////////////////////////////////////////////////////////
// Параметры ключа СТБ 34.101
////////////////////////////////////////////////////////////////////////////////
public class Parameters extends ECParameterSpec implements IParameters
{
    private static final long serialVersionUID = 2232571374244238399L;
    
    // выполнить преобразование типа
    public static Parameters convert(IParameters parameters)
    {
        // проверить тип параметров
        if (parameters instanceof Parameters) return (Parameters)parameters; 
        
        // выполнить преобразование типа
        return new Parameters(parameters.getCurve(), 
            parameters.getGenerator(), parameters.getOrder()
        ); 
    }
    // конструктор
    public static IParameters getInstance(AlgorithmParameterSpec paramSpec) 
        throws InvalidParameterSpecException
    { 
        // проверить требуемый тип данных
        if (paramSpec instanceof ECParameterSpec)
        {
            // выполнить преобразование типа
            if (paramSpec instanceof IParameters) return (IParameters)paramSpec; 
            
            // выполнить преобразование типа
            ECParameterSpec ecParamSpec = (ECParameterSpec)paramSpec; 
        
            // проверить корректность параметров
            if (ecParamSpec.getCofactor() != 1) throw new InvalidParameterSpecException(); 
            try { 
                // преобразовать тип кривой
                CurveFp curve = CurveFp.convert(ecParamSpec.getCurve());
        
                // создать параметры ключа
                return new Parameters(curve, ecParamSpec.getGenerator(), ecParamSpec.getOrder()); 
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
    public Parameters(CurveFp ec, ECPoint g, BigInteger q)
    {
        // сохранить переданные параметры
        super(ec, g, q, 1); 
        
        // проверить корректность данных
        if (g.getAffineX().signum() != 0) throw new IllegalArgumentException(); 
    }
    // используемая эллиптическая кривая
	@Override public final CurveFp getCurve() { return (CurveFp)super.getCurve(); }
    
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
