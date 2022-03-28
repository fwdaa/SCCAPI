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
}
