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
    public Parameters(CurveFp ec, ECPoint g, BigInteger q)
    {
        // сохранить переданные параметры
        super(ec, g, q, 1); 
        
        // проверить корректность данных
        if (g.getAffineX().signum() != 0) throw new IllegalArgumentException(); 
    }
    // используемая эллиптическая кривая
	@Override public final CurveFp getCurve() { return (CurveFp)super.getCurve(); }
}
