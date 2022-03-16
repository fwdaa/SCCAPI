using System; 
using System.Runtime.Serialization;

namespace Aladdin.ASN1.ANSI.X962
{
    ////////////////////////////////////////////////////////////////////////////////
    // ECDSA-Full-R ::= SEQUENCE {
    //      r ECPoint,
    //      s INTEGER
    // }
    ////////////////////////////////////////////////////////////////////////////////
	[Serializable]
    public class ECDSAFullR : Sequence
    {
	    // информация о структуре
	    private static readonly ObjectInfo[] info = new ObjectInfo[] { 
        
		    new ObjectInfo(new ObjectCreator<OctetString>().Factory(), Cast.N), 
		    new ObjectInfo(new ObjectCreator<Integer    >().Factory(), Cast.N), 
	    }; 
		// конструктор при сериализации
        protected ECDSAFullR(SerializationInfo info, StreamingContext context) : base(info, context) {}

	    // конструктор при раскодировании
	    public ECDSAFullR(IEncodable encodable) : base(encodable, info) {}
    
	    // конструктор при закодировании
	    public ECDSAFullR(OctetString r, Integer s) : base(info, r, s) {}
    
	    public OctetString R { get { return (OctetString)this[0]; }} 
	    public Integer     S { get { return (Integer    )this[1]; }} 
    }
}
