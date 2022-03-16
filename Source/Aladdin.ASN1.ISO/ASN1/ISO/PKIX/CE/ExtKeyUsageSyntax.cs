using System; 
using System.Runtime.Serialization;

// ExtKeyUsageSyntax ::= SEQUENCE OF OBJECT IDENTIFIER

namespace Aladdin.ASN1.ISO.PKIX.CE
{
	[Serializable]
	public class ExtKeyUsageSyntax : Sequence<ObjectIdentifier>
	{
		// конструктор при сериализации
        protected ExtKeyUsageSyntax(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public ExtKeyUsageSyntax(IEncodable encodable) : base(encodable) {}

		// конструктор при закодировании
		public ExtKeyUsageSyntax(params ObjectIdentifier[] values) : base(values) {}
	}
}
