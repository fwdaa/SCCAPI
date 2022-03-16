using System; 
using System.Runtime.Serialization;

namespace Aladdin.ASN1.ANSI.X962
{
    // ECPoints ::= SEQUENCE OF ECPoint

	[Serializable]
    public class ECPoints : Sequence<OctetString>
    {
		// конструктор при сериализации
        protected ECPoints(SerializationInfo info, StreamingContext context) : base(info, context) {}

	    // конструктор при раскодировании
	    public ECPoints(IEncodable encodable) : base(encodable) {} 

	    // конструктор при закодировании
	    public ECPoints(params OctetString[] values) : base(values) {} 
    }
}