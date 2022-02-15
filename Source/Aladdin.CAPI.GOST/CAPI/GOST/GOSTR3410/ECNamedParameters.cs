///////////////////////////////////////////////////////////////////////////
// Именованные параметры ГОСТ Р34.10
///////////////////////////////////////////////////////////////////////////
namespace Aladdin.CAPI.GOST.GOSTR3410
{
    public class ECNamedParameters : ECParameters, INamedParameters 
    {
        // выполнить преобразование типа
        public static ECNamedParameters Convert(INamedParameters parameters)
        {
            // проверить тип объекта
            if (parameters is ECNamedParameters) return (ECNamedParameters)parameters;
        
            // выполнить преобразование типа
            return Create(parameters.ParamOID, parameters.HashOID, parameters.SBoxOID); 
        }
        // создать параметры
        public static ECNamedParameters Create(string paramOID, string hashOID, string sboxOID)
        {
            // при указании идентификатора таблицы пдстановок для хэширования
            if (hashOID.StartsWith(ASN1.GOST.OID.hashes))
            {
                // создать параметры ключа ГОСТ Р34.10-2001
                return new ECNamedParameters2001(paramOID, hashOID, sboxOID); 
            }
            // создать параметры ключа ГОСТ Р34.10-2012
            else return new ECNamedParameters2012(paramOID, hashOID); 
        }
        // конструктор
        public ECNamedParameters(string paramOID, string hashOID, string sboxOID) 

            // сохранить переданные параметры
            : base(ASN1.GOST.GOSTR3410ParamSet.Parameters(paramOID)) 
        {
            // сохранить переданные параметры
            this.paramOID = paramOID; this.hashOID = hashOID; this.sboxOID = sboxOID; 
        }
	    public string ParamOID { get { return paramOID; }} private string paramOID;
	    public string HashOID  { get { return  hashOID; }} private string hashOID;
	    public string SBoxOID  { get { return  sboxOID; }} private string sboxOID;
    }
}
