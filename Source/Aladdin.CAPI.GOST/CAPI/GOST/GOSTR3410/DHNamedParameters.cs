using System; 

namespace Aladdin.CAPI.GOST.GOSTR3410
{
    ///////////////////////////////////////////////////////////////////////////
    // Именованные параметры ГОСТ Р34.10-1994
    ///////////////////////////////////////////////////////////////////////////
    [Serializable]
    public class DHNamedParameters : DHParameters, INamedParameters
    {
        // выполнить преобразование типа
        public static DHNamedParameters Convert(INamedParameters parameters)
        {
            // проверить тип объекта
            if (parameters is DHNamedParameters) return (DHNamedParameters)parameters;
        
            // выполнить преобразование типа
            return new DHNamedParameters(parameters.ParamOID, parameters.HashOID, parameters.SBoxOID); 
        }
        // конструктор
        public DHNamedParameters(string paramOID, string hashOID, string sboxOID) 

            // сохранить переданные параметры
            : base(ASN1.GOST.GOSTR3410ParamSet1994.Parameters(paramOID)) 
        {
            // сохранить переданные параметры
            this.paramOID = paramOID; this.hashOID = hashOID; this.sboxOID = sboxOID; 
        }
        // конструктор
        public DHNamedParameters(ASN1.GOST.GOSTR3410PublicKeyParameters2001 parameters) 

            // сохранить переданные параметры
            : this(parameters.PublicKeyParamSet .Value, 
                   parameters.DigestParamSet    .Value, 
                   parameters.EncryptionParamSet.Value) {} 
        
	    public string ParamOID { get { return paramOID; }} private string paramOID;
	    public string HashOID  { get { return  hashOID; }} private string hashOID;
	    public string SBoxOID  { get { return  sboxOID; }} private string sboxOID;
    }
}
