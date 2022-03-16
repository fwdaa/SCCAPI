using System; 

///////////////////////////////////////////////////////////////////////////////
// Именованный набор параметров
///////////////////////////////////////////////////////////////////////////////
namespace Aladdin.CAPI.STB.STB11762
{
    [Serializable]
    public class BDHNamedParameters : BDHParameters, INamedParameters 
    {
        // конструктор
        public BDHNamedParameters(string oid, ASN1.STB.BDHParamsList list) : base(list) { this.oid = oid; }
    
        // идентификатор параметорв
        public string Oid { get { return oid; }} private string oid; 
    }
}
