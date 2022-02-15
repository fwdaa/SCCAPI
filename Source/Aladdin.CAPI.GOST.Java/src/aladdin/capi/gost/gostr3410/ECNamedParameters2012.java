package aladdin.capi.gost.gostr3410;
import aladdin.asn1.gost.*; 

///////////////////////////////////////////////////////////////////////////
// Именованные параметры ГОСТ Р34.10-2012
///////////////////////////////////////////////////////////////////////////
public class ECNamedParameters2012 extends ECNamedParameters
{
    // конструктор
    public ECNamedParameters2012(String paramOID, String hashOID) 
    {
        // сохранить переданные параметры
        super(paramOID, hashOID, OID.ENCRYPTS_TC26_Z); 
    }
    // конструктор
    public ECNamedParameters2012(GOSTR3410PublicKeyParameters2012 parameters, int bits) 
    {
        // сохранить переданные параметры
        this(parameters.publicKeyParamSet().value(), (parameters.digestParamSet() != null) ? 
             parameters.digestParamSet   ().value() : (
                bits == 256 ? OID.GOSTR3411_2012_256 : OID.GOSTR3411_2012_512
        )); 
    }
}
