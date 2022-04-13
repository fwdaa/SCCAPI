package aladdin.capi.stb.stb11762;
import aladdin.asn1.stb.*;
import java.math.*;
import java.security.spec.*;
import javax.crypto.spec.*; 

///////////////////////////////////////////////////////////////////////
// Параметры обмена
///////////////////////////////////////////////////////////////////////
public class BDHParameters extends DHParameterSpec implements IBDHParameters
{
    private static final long serialVersionUID = 5383091543128678349L;
    
    // конструктор
    public static IBDHParameters getInstance(AlgorithmParameterSpec paramSpec) 
        throws InvalidParameterSpecException
    { 
        // в зависимости от типа данных
        if (paramSpec instanceof DHParameterSpec)
        {
            // выполнить преобразование типа
            if (paramSpec instanceof IBDHParameters) return (IBDHParameters)paramSpec; 
        }
        // тип параметров не поддерживается 
        throw new InvalidParameterSpecException(); 
    }
    // параметры обмена
    private final int l; private final int r; private final byte[] z;	
    
    // конструктор
    public BDHParameters(int l, int r, BigInteger p, BigInteger g, int n, byte[] z) 
    {
        // сохранить переданные параметры
        super(p, g, n); this.l = l; this.r = r; this.z = z; 
    }
    public BDHParameters(BDHParamsList list)
    {
        // сохранить переданные параметры
        super(list.bdhParameterP().value(), list.bdhParameterG().value(), 
            list.bdhParameterN().value().intValue()
        );
        // получить параметры l, r и N
        l = list.bdhParameterL().value().intValue(); 
        r = list.bdhParameterR().value().intValue(); 

        // проверить наличие параметров генерации
        if (list.bdhParamInitData() == null) z = null; 
        else {
            // получить параметры генерации
            z = list.bdhParamInitData().bdhPrmsInitZSequence().value();
        }
    }
    @Override public int        bdhL() { return l; } 
    @Override public int        bdhR() { return r; } 
    @Override public BigInteger bdhP() { return getP(); } 
    @Override public BigInteger bdhG() { return getG(); } 
    @Override public int        bdhN() { return getL(); } 
    @Override public byte[]     bdhZ() { return z; } 
    
    @SuppressWarnings({"unchecked"}) 
    @Override public <T extends AlgorithmParameterSpec> 
        T getParameterSpec(Class<T> specType) 
            throws InvalidParameterSpecException
    {
        // вернуть параметры
        if (specType.isAssignableFrom(DHParameterSpec.class)) return (T)this; 
        
        // тип параметров не поддерживается 
        throw new InvalidParameterSpecException(); 
    }
}
