namespace Aladdin.CAPI.ANSI.X962
{
    ///////////////////////////////////////////////////////////////////////////////
    // Именованный набор параметров
    ///////////////////////////////////////////////////////////////////////////////
    public class NamedParameters : Parameters, INamedParameters 
    {
        // конструктор
        public NamedParameters(string oid, EC.Curve curve, EC.Point g, 
            Math.BigInteger n, Math.BigInteger h, ASN1.ISO.AlgorithmIdentifier hash)
         
            // сохранить переданные параметры
            : base(curve, g, n, h, hash) { this.oid = oid; }
        
        // идентификатор параметорв
        public string Oid { get { return oid; }} private string oid; 
    }
}
