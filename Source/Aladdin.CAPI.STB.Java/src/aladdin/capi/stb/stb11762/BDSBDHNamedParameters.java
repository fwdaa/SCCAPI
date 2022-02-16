package aladdin.capi.stb.stb11762;
import aladdin.asn1.stb.*;
import aladdin.capi.*; 

///////////////////////////////////////////////////////////////////////////////
// Именованный набор параметров
///////////////////////////////////////////////////////////////////////////////
public class BDSBDHNamedParameters extends BDSBDHParameters implements INamedParameters 
{
    // конструктор
    public BDSBDHNamedParameters(String oid, BDSBDHParamsList list) { super(list); this.oid = oid; }
    
    // идентификатор параметорв
    @Override public final String oid() { return oid; } private final String oid; 
}