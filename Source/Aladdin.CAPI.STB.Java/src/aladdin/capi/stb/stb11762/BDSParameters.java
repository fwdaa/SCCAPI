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
}
