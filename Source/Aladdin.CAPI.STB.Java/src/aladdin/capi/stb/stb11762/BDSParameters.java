package aladdin.capi.stb.stb11762;
import aladdin.asn1.stb.*;
import java.security.spec.*; 
import java.math.*;

///////////////////////////////////////////////////////////////////////
// Параметры подписи
///////////////////////////////////////////////////////////////////////
public class BDSParameters extends DSAParameterSpec implements IBDSParameters
{
    private static final long serialVersionUID = 6836485618865537858L;
    
    // конструктор
    public static IBDSParameters getInstance(AlgorithmParameterSpec paramSpec) 
        throws InvalidParameterSpecException
    { 
        // выполнить преобразование типа
        if (paramSpec instanceof IBDSParameters) return (IBDSParameters)paramSpec; 
            
        // в зависимости от типа данных
        if (paramSpec instanceof DSAParameterSpec)
        {
            // выполнить преобразование типа
            DSAParameterSpec dsaParamSpec = (DSAParameterSpec)paramSpec; 
            
            // вычислить параметры L и R
            int l = dsaParamSpec.getP().bitLength(); 
            int r = dsaParamSpec.getQ().bitLength(); 
            
            // создать параметры ключа
            return new BDSParameters(l, r, dsaParamSpec.getP(), 
                dsaParamSpec.getQ(), dsaParamSpec.getG(), new byte[32], null
            ); 
        }
        // тип параметров не поддерживается
        throw new InvalidParameterSpecException(); 
    }
    // конструктор
    public BDSParameters(int l, int r, BigInteger p, BigInteger q, BigInteger a, byte[] h, byte[] z)
    {
        // сохранить переданные параметры
        super(p, q, a); this.l = l; this.r = r; this.h = h; this.z = z;
    }
    public BDSParameters(BDSParamsList list)
    {
        // сохранить переданные параметры
        super(list.bdsParameterP().value(), 
              list.bdsParameterQ().value(), 
              list.bdsParameterA().value()
        ); 
        // получить параметры l и r
        l = list.bdsParameterL().value().intValue(); 
        r = list.bdsParameterR().value().intValue(); 

        // получить закодированный параметр H
        h = list.bdsParameterH().value();  
        
        // проверить наличие параметров генерации
        if (list.bdsParamInitData() == null) z = null; 
        else {
            // получить параметры генерации
            z = list.bdsParamInitData().bdsPrmsInitZSequence().value();
        }
    }
    @Override public int        bdsL() { return l; } private final int		  l;
    @Override public int        bdsR() { return r; } private final int		  r;
    @Override public byte[]     bdsH() { return h; } private final byte[]	  h;
    @Override public byte[]     bdsZ() { return z; } private final byte[]	  z;

    @Override public BigInteger bdsP() { return getP(); } 
    @Override public BigInteger bdsQ() { return getQ(); } 
    @Override public BigInteger bdsA() { return getG(); } 
    
    @SuppressWarnings({"unchecked"}) 
    @Override public <T extends AlgorithmParameterSpec> 
        T getParameterSpec(Class<T> specType) 
            throws InvalidParameterSpecException
    {
        // вернуть параметры
        if (specType.isAssignableFrom(IBDSParameters.class)) return (T)this; 
        
        // вернуть параметры
        if (specType.isAssignableFrom(DSAParameterSpec.class)) return (T)this; 
        
        // тип параметров не поддерживается
        throw new InvalidParameterSpecException(); 
    }
}
