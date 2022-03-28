package aladdin.capi.stb.stb11762;
import aladdin.asn1.stb.*;
import java.math.*;
import javax.crypto.spec.*; 

///////////////////////////////////////////////////////////////////////
// Параметры обмена
///////////////////////////////////////////////////////////////////////
public class BDHParameters extends DHParameterSpec implements IBDHParameters
{
    private static final long serialVersionUID = 5383091543128678349L;
    
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
}
