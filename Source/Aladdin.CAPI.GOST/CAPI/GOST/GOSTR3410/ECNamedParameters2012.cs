using System; 

///////////////////////////////////////////////////////////////////////////
// Именованные параметры ГОСТ Р34.10-2012
///////////////////////////////////////////////////////////////////////////
namespace Aladdin.CAPI.GOST.GOSTR3410
{
    [Serializable]
    public class ECNamedParameters2012 : ECNamedParameters
    {
        // конструктор
        public ECNamedParameters2012(string paramOID, string hashOID) 

            // сохранить переданные параметры
            : base(paramOID, hashOID, ASN1.GOST.OID.encrypts_tc26_z) {}
        
        // конструктор
        public ECNamedParameters2012(ASN1.GOST.GOSTR3410PublicKeyParameters2012 parameters, int bits) 

            // сохранить переданные параметры
            : this(parameters.PublicKeyParamSet.Value, (parameters.DigestParamSet != null) ? 
                   parameters.DigestParamSet   .Value : (
                        bits == 256 ? ASN1.GOST.OID.gostR3411_2012_256 : ASN1.GOST.OID.gostR3411_2012_512
            )) {}
    }
}
