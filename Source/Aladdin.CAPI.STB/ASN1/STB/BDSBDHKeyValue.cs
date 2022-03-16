using System; 
using System.Runtime.Serialization;

namespace Aladdin.ASN1.STB
{
    ///////////////////////////////////////////////////////////////////////////////
    // BDSKeyValue ::= INTEGER
    // BDSBDHKeyValue ::= SEQUENCE {
    // 		bdsKey INTEGER,
    // 		bdhKey INTEGER
    // 	}
    ///////////////////////////////////////////////////////////////////////////////
    [Serializable]
    public class BDSBDHKeyValue : Sequence 
    {
	    // информация о структуре
	    private static readonly ObjectInfo[] info = new ObjectInfo[] { 
        
		    new ObjectInfo(new ObjectCreator<Integer>().Factory(), Cast.N),
		    new ObjectInfo(new ObjectCreator<Integer>().Factory(), Cast.N) 
	    }; 
		// конструктор при сериализации
        protected BDSBDHKeyValue(SerializationInfo info, StreamingContext context) : base(info, context) {}

	    // конструктор при раскодировании
	    public BDSBDHKeyValue(IEncodable encodable) : base(encodable, info) {}  
    
	    // конструктор при закодировании
	    public BDSBDHKeyValue(Integer bdsKey, Integer bdhKey) : base(info, bdsKey, bdhKey) {} 

	    public Integer BDSKey { get { return (Integer)this[0]; }}
	    public Integer BDHKey { get { return (Integer)this[1]; }} 
    }
}
