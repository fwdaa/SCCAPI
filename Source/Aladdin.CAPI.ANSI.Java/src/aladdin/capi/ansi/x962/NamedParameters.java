package aladdin.capi.ansi.x962;
import aladdin.asn1.iso.*;
import aladdin.capi.*; 
import java.math.*; 

///////////////////////////////////////////////////////////////////////////////
// Именованный набор параметров
///////////////////////////////////////////////////////////////////////////////
public class NamedParameters extends Parameters implements INamedParameters 
{
    private static final long serialVersionUID = -5477801709063940959L;
    
    // конструктор
    public NamedParameters(String oid, aladdin.capi.ec.Curve curve, 
        java.security.spec.ECPoint g, BigInteger n, int h, AlgorithmIdentifier hash)
    { 
        // сохранить переданные параметры
        super(curve, g, n, h, hash); this.oid = oid; 
    }
    // идентификатор параметорв
    @Override public final String oid() { return oid; } private final String oid; 
}
