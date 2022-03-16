using System; 

///////////////////////////////////////////////////////////////////////////////
// Именованный набор параметров
///////////////////////////////////////////////////////////////////////////////
namespace Aladdin.CAPI.STB.STB11762
{
    [Serializable]
    public class BDSNamedParameters : BDSParameters, INamedParameters 
    {
        // конструктор
        public BDSNamedParameters(string oid, ASN1.STB.BDSParamsList list) : base(list) { this.oid = oid; }
    
        // идентификатор параметорв
        public string Oid { get { return oid; }} private string oid; 
    }
}
