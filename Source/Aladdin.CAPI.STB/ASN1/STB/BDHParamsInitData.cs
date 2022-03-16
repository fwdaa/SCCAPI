using System; 
using System.Runtime.Serialization;

namespace Aladdin.ASN1.STB
{
    ///////////////////////////////////////////////////////////////////////////////
    //	BDHParamsInitData ::= SEQUENCE {
    //		bdhPrmsInitZSequence OCTET STRING,
    //		bdhPrmsInitLSequence OCTET STRING
    //	}
    ///////////////////////////////////////////////////////////////////////////////
    [Serializable]
    public class BDHParamsInitData : Sequence 
    {
	    // информация о структуре
	    private static readonly ObjectInfo[] info = new ObjectInfo[] { 
        
		    new ObjectInfo(new ObjectCreator<OctetString>().Factory(), Cast.N), 
		    new ObjectInfo(new ObjectCreator<OctetString>().Factory(), Cast.N), 
	    }; 
		// конструктор при сериализации
        protected BDHParamsInitData(SerializationInfo info, StreamingContext context) : base(info, context) {}

	    // конструктор при раскодировании
	    public BDHParamsInitData(IEncodable encodable) : base(encodable, info) {}  
    
	    // конструктор при закодировании
	    public BDHParamsInitData(OctetString bdhPrmsInitZSequence, OctetString bdhPrmsInitLSequence)
		    : base(info, bdhPrmsInitZSequence, bdhPrmsInitLSequence) {} 

	    public OctetString BDHPrmsInitZSequence { get { return (OctetString)this[0]; }} 
	    public OctetString BDHPrmsInitLSequence { get { return (OctetString)this[1]; }} 
    }
}
