using System; 
using System.Runtime.Serialization;

namespace Aladdin.ASN1.ANSI.X962
{
    ////////////////////////////////////////////////////////////////////////////////
    // SpecifiedMultiples ::= SEQUENCE OF SpecifiedMultiple
    ////////////////////////////////////////////////////////////////////////////////
	[Serializable]
    public class SpecifiedMultiples : Sequence<SpecifiedMultiple>
    {
		// конструктор при сериализации
        protected SpecifiedMultiples(SerializationInfo info, StreamingContext context) : base(info, context) {}

	    // конструктор при раскодировании
	    public SpecifiedMultiples(IEncodable encodable) : base(encodable) {}  

	    // конструктор при закодировании
	    public SpecifiedMultiples(params SpecifiedMultiple[] values) : base(values) {} 
    }
}