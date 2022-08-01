using System;
using System.Runtime.Serialization;

// PreferredSignatureAlgorithms ::= SEQUENCE OF PreferredSignatureAlgorithm

namespace Aladdin.ASN1.ISO.OCSP
{
	[Serializable]
	public class PreferredSignatureAlgorithms : Sequence<PreferredSignatureAlgorithm>
	{
		// конструктор при сериализации
        protected PreferredSignatureAlgorithms(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public PreferredSignatureAlgorithms(IEncodable encodable) : base(encodable) {}

		// конструктор при закодировании
		public PreferredSignatureAlgorithms(params PreferredSignatureAlgorithm[] values) : base(values) {}
	}
}
