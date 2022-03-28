package aladdin.capi.stb.stb11762;
import aladdin.asn1.stb.*;
import aladdin.capi.*; 

///////////////////////////////////////////////////////////////////////////////
// Именованный набор параметров
///////////////////////////////////////////////////////////////////////////////
public class BDSNamedParameters extends BDSParameters implements INamedParameters 
{
    private static final long serialVersionUID = -5650818344497538372L;
    
    // конструктор
    public BDSNamedParameters(String oid, BDSParamsList list) { super(list); this.oid = oid; }
    
    // идентификатор параметорв
    @Override public final String oid() { return oid; } private final String oid; 
}
