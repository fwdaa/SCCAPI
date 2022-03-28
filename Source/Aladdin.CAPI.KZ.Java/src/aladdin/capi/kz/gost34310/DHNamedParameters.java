package aladdin.capi.kz.gost34310;
import aladdin.asn1.gost.*; 
import aladdin.capi.*; 
import java.io.*; 

////////////////////////////////////////////////////////////////////////////////
// Именованный набор параметров ГОСТ Р34.310-94
////////////////////////////////////////////////////////////////////////////////
public class DHNamedParameters extends aladdin.capi.gost.gostr3410.DHNamedParameters
    implements INamedParameters
{    
    private static final long serialVersionUID = 7981178530133119288L;    
    
    // конструктор
    public DHNamedParameters(String oid, String paramOID) throws IOException
    {
        // сохранить переданные параметры
        super(paramOID, OID.HASHES_TEST, OID.HASHES_TEST); this.oid = oid; 
    }
    // идентификатор набора параметров
    @Override public String oid() { return oid; } private final String oid; 
}
