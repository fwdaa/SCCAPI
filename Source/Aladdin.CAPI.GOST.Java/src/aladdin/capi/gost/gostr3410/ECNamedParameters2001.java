package aladdin.capi.gost.gostr3410;
import aladdin.asn1.gost.*; 

///////////////////////////////////////////////////////////////////////////
// Именованные параметры ГОСТ Р34.10-2001
///////////////////////////////////////////////////////////////////////////
public class ECNamedParameters2001 extends ECNamedParameters
{
    private static final long serialVersionUID = 7109000608280586846L;
    
    // конструктор
    public ECNamedParameters2001(String paramOID, String hashOID, String sboxOID) 
    {
        // сохранить переданные параметры
        super(paramOID, hashOID, sboxOID); 
    }
    // конструктор
    public ECNamedParameters2001(GOSTR3410PublicKeyParameters2001 parameters) 
    {
        // сохранить переданные параметры
        this(parameters.publicKeyParamSet ().value(), 
             parameters.digestParamSet    ().value(), 
             parameters.encryptionParamSet().value()
        ); 
    }
}
