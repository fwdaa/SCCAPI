using System;
using System.Runtime.Serialization;

// RevokedCertificates ::= SEQUENCE OF RevokedCertificate

namespace Aladdin.ASN1.ISO.PKIX
{
	[Serializable]
	public class RevokedCertificates : Sequence<RevokedCertificate>
	{
		// конструктор при сериализации
        protected RevokedCertificates(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public RevokedCertificates(IEncodable encodable) : base(encodable) {} 

		// конструктор при закодировании
		public RevokedCertificates(params RevokedCertificate[] values) : base(values) {} 
	}
}
