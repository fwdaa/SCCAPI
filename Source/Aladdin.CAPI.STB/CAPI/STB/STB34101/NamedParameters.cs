///////////////////////////////////////////////////////////////////////////////
// Именованный набор параметров
///////////////////////////////////////////////////////////////////////////////
namespace Aladdin.CAPI.STB.STB34101
{
    public class NamedParameters : Parameters, INamedParameters 
    {
        // конструктор
        public NamedParameters(string oid, EC.CurveFp ec, EC.Point g, Math.BigInteger q)
         
            // сохранить переданные параметры
            : base(ec, g, q) { this.oid = oid; }
        
        // идентификатор параметорв
        public string Oid { get { return oid; }} private string oid; 
    }
}
