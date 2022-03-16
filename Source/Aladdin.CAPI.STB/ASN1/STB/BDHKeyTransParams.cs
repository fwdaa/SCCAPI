using System; 
using System.Runtime.Serialization;

namespace Aladdin.ASN1.STB
{
    ////////////////////////////////////////////////////////////////////////////////
    // BDHKeytransParams ::= SEQUENCE {
    // 		va INTEGER,
    // 		mac OCTET STRING (SIZE(4)),
    // 		sblock OBJECT IDENTIFIER OPTIONAL
    // 	}
    ////////////////////////////////////////////////////////////////////////////////
    [Serializable]
    public class BDHKeyTransParams : Sequence
    {
	    // информация о структуре
	    private static readonly ObjectInfo[] info = new ObjectInfo[] { 

            new ObjectInfo(new ObjectCreator<Integer         >().Factory(    ), Cast.N), 
            new ObjectInfo(new ObjectCreator<OctetString 	 >().Factory(4, 4), Cast.N), 
		    new ObjectInfo(new ObjectCreator<ObjectIdentifier>().Factory(    ), Cast.O) 
	    }; 
		// конструктор при сериализации
        protected BDHKeyTransParams(SerializationInfo info, StreamingContext context) : base(info, context) {}

	    // конструктор при раскодировании
	    public BDHKeyTransParams(IEncodable encodable) : base(encodable, info) {} 
    
	    // конструктор при закодировании
	    public BDHKeyTransParams(Integer va, OctetString mac, ObjectIdentifier sblock) 
		    : base(info, va, mac, sblock) {}

	    public Integer          Va     { get { return (Integer	       )this[0]; }}
	    public OctetString		Mac    { get { return (OctetString	   )this[1]; }} 
	    public ObjectIdentifier	SBlock { get { return (ObjectIdentifier)this[2]; }}
    }
}
