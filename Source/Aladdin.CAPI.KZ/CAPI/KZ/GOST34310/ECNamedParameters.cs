namespace Aladdin.CAPI.KZ.GOST34310
{ 
    ////////////////////////////////////////////////////////////////////////////////
    // Именованный набор параметров ГОСТ Р34.310-2001,2012
    ////////////////////////////////////////////////////////////////////////////////
    public class ECNamedParameters : GOST.GOSTR3410.ECNamedParameters2001, INamedParameters
    {    
        // конструктор
        public ECNamedParameters(string oid, string paramOID) 
        
            // сохранить переданные параметры
            : base(paramOID, ASN1.GOST.OID.hashes_test, ASN1.KZ.OID.gamma_gost28147_param_g) { this.oid = oid; }
        
        // идентификатор набора параметров
        public string Oid { get { return oid; }} private string oid; 
    }
}
