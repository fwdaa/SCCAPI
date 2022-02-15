///////////////////////////////////////////////////////////////////////////
// Именованные параметры ГОСТ Р34.10-2001
///////////////////////////////////////////////////////////////////////////
namespace Aladdin.CAPI.GOST.GOSTR3410
{
    public class ECNamedParameters2001 : ECNamedParameters
    {
        // конструктор
        public ECNamedParameters2001(string paramOID, string hashOID, string sboxOID) 

            // сохранить переданные параметры
            : base(paramOID, hashOID, sboxOID) {}

        // конструктор
        public ECNamedParameters2001(ASN1.GOST.GOSTR3410PublicKeyParameters2001 parameters) 

            // сохранить переданные параметры
            : this(parameters.PublicKeyParamSet .Value, 
                   parameters.DigestParamSet    .Value, 
                   parameters.EncryptionParamSet.Value) {} 
    }
}