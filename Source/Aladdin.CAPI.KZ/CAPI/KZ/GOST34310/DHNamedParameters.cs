namespace Aladdin.CAPI.KZ.GOST34310
{ 
    ////////////////////////////////////////////////////////////////////////////////
    // Именованный набор параметров ГОСТ Р34.310-94
    ////////////////////////////////////////////////////////////////////////////////
    public class DHNamedParameters : GOST.GOSTR3410.DHNamedParameters, INamedParameters
    {    
        // конструктор
        public DHNamedParameters(string oid, string paramOID) 
        
            // сохранить переданные параметры
            : base(paramOID, ASN1.GOST.OID.hashes_test, ASN1.KZ.OID.gamma_gost28147_param_g) { this.oid = oid; }

        // идентификатор набора параметров
        public string Oid { get { return oid; }} private string oid; 
    }
}
