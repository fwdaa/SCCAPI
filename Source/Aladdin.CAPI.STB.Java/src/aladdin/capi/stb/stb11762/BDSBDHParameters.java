package aladdin.capi.stb.stb11762;
import aladdin.asn1.stb.*;
import java.security.spec.*; 
import java.math.*;
import javax.crypto.spec.*;

///////////////////////////////////////////////////////////////////////
// Параметры подписи с параметрами обмена
///////////////////////////////////////////////////////////////////////
public class BDSBDHParameters extends DSAParameterSpec implements IBDSBDHParameters
{
    private static final long serialVersionUID = -4786163540825284235L;
    
    // конструктор
    public static IBDSBDHParameters getInstance(AlgorithmParameterSpec paramSpec)
        throws InvalidParameterSpecException
    { 
        // выполнить преобразование типа
        if (paramSpec instanceof IBDSBDHParameters) return (IBDSBDHParameters)paramSpec; 
        
        // тип параметров не поддерживается
        throw new InvalidParameterSpecException(); 
    }
    // конструктор
    public BDSBDHParameters(IBDSParameters bdsParameters, IBDHParameters bdhParameters)
    {
        // сохранить переданные параметры
        super(bdsParameters.getP(), bdsParameters.getQ(), bdsParameters.getG()); 
        
        // сохранить переданные параметры
        this.bdsParameters = bdsParameters; this.bdhParameters = bdhParameters; 
    }
    // конструктор
    public BDSBDHParameters(BDSBDHParamsList list)
    {
        // сохранить переданные параметры
        this(new BDSParameters(list.bdsParamsList()), new BDHParameters(list.bdhParamsList())); 
    }
    @Override public final int        bdsL() { return bdsParameters.bdsL(); }
    @Override public final int        bdsR() { return bdsParameters.bdsR(); }
    @Override public final BigInteger bdsP() { return bdsParameters.bdsP(); }
    @Override public final BigInteger bdsQ() { return bdsParameters.bdsQ(); } 
    @Override public final BigInteger bdsA() { return bdsParameters.bdsA(); } 
    @Override public final byte[]     bdsH() { return bdsParameters.bdsH(); } 
    @Override public final byte[]     bdsZ() { return bdsParameters.bdsZ(); } 
    
    @Override public final int        bdhL() { return bdhParameters.bdhL(); }
    @Override public final int        bdhR() { return bdhParameters.bdhR(); }
    @Override public final BigInteger bdhP() { return bdhParameters.bdhP(); }
    @Override public final BigInteger bdhG() { return bdhParameters.bdhG(); } 
    @Override public final int        bdhN() { return bdhParameters.bdhN(); } 
    @Override public final byte[]     bdhZ() { return bdhParameters.bdhZ(); } 

    private final IBDSParameters	bdsParameters;		// параметры подписи 
    private final IBDHParameters	bdhParameters;		// параметры обмена

    @SuppressWarnings({"unchecked"}) 
    @Override public <T extends AlgorithmParameterSpec> 
        T getParameterSpec(Class<T> specType) 
            throws InvalidParameterSpecException
    {
        // вернуть параметры
        if (specType.isAssignableFrom(IBDSBDHParameters.class)) return (T)this;
        
        // вернуть параметры
        if (specType.isAssignableFrom(DSAParameterSpec.class)) return (T)this;
        
        // в зависимости от типа данных
        if (specType.isAssignableFrom(DHParameterSpec.class))
        {
            // вернуть параметры ключа
            return (T)new DHParameterSpec(bdhP(), bdhG(), bdhN()); 
        }
        // тип параметров не поддерживается
        throw new InvalidParameterSpecException(); 
    }
}
