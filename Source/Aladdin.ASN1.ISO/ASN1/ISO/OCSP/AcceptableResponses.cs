using System;
using System.Runtime.Serialization;

// AcceptableResponses ::= SEQUENCE OF RESPONSE.&id({ResponseSet})

namespace Aladdin.ASN1.ISO.OCSP
{
	[Serializable]
	public class AcceptableResponses : Sequence<ObjectIdentifier>
	{
		// конструктор при сериализации
        protected AcceptableResponses(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public AcceptableResponses(IEncodable encodable) : base(encodable) {}

		// конструктор при закодировании
		public AcceptableResponses(params ObjectIdentifier[] values) : base(values) {}
	}
}
