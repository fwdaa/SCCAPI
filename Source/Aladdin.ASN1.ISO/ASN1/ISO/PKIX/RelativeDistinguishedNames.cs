using System;
using System.Runtime.Serialization;

// RelativeDistinguishedNames ::= SEQUENCE OF RelativeDistinguishedName

namespace Aladdin.ASN1.ISO.PKIX
{
	[Serializable]
	public class RelativeDistinguishedNames : Sequence<RelativeDistinguishedName>
	{
		// конструктор при сериализации
        protected RelativeDistinguishedNames(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public RelativeDistinguishedNames(IEncodable encodable) : base(encodable) {}

		// конструктор при закодировании
		public RelativeDistinguishedNames(params RelativeDistinguishedName[] values) : base(values) {}
	}
}
