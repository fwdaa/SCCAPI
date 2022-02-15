package aladdin.capi.kz.gost34310;
import aladdin.asn1.kz.*; 
import aladdin.capi.*; 

////////////////////////////////////////////////////////////////////////////////
// Именованный набор параметров ГОСТ Р34.310-2001,2012
////////////////////////////////////////////////////////////////////////////////
public class ECNamedParameters extends aladdin.capi.gost.gostr3410.ECNamedParameters2001
    implements INamedParameters
{    
    // конструктор
    public ECNamedParameters(String oid, String paramOID) 
    {
        // сохранить переданные параметры
        super(paramOID, aladdin.asn1.gost.OID.HASHES_TEST, OID.GAMMA_GOST28147_PARAM_G); this.oid = oid; 
    }
    // идентификатор набора параметров
    @Override public String oid() { return oid; } private final String oid; 
}
