using System;
using System.Runtime.Serialization;

// Addresses ::= SET OF OCTET STRING 

namespace Aladdin.ASN1.ISO.PKIX.X400
{
	[Serializable]
	public class Addresses : Set<OctetString>
	{
		// конструктор при сериализации
        protected Addresses(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public Addresses(IEncodable encodable) : base(encodable) {}

		// конструктор при закодировании
		public Addresses(params OctetString[] values) : base(values) {}
	}
}
