package aladdin.capi.stb.stb11762;
import aladdin.asn1.stb.*;
import aladdin.capi.*; 

///////////////////////////////////////////////////////////////////////////////
// Именованный набор параметров
///////////////////////////////////////////////////////////////////////////////
public class BDHNamedParameters extends BDHParameters implements INamedParameters 
{
    private static final long serialVersionUID = -2939266454327744160L;
    
    // конструктор
    public BDHNamedParameters(String oid, BDHParamsList list) { super(list); this.oid = oid; }
    
    // идентификатор параметорв
    @Override public final String oid() { return oid; } private final String oid; 
}
