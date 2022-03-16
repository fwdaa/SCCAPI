using System; 

///////////////////////////////////////////////////////////////////////////////
// Именованный набор параметров
///////////////////////////////////////////////////////////////////////////////
namespace Aladdin.CAPI.STB.STB11762
{
    [Serializable]
    public class BDSBDHNamedParameters : BDSBDHParameters, INamedParameters 
    {
        // конструктор
        public BDSBDHNamedParameters(string oid, ASN1.STB.BDSBDHParamsList list) 
            
            // сохранить переданные параметры
            : base(list) { this.oid = oid; }
    
        // идентификатор параметорв
        public string Oid { get { return oid; }} private string oid; 
    }
}
