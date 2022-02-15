using System;

// RevokedCertificates ::= SEQUENCE OF RevokedCertificate

namespace Aladdin.ASN1.ISO.PKIX
{
	public class RevokedCertificates : Sequence<RevokedCertificate>
	{
		// конструктор при раскодировании
		public RevokedCertificates(IEncodable encodable) : base(encodable) {} 

		// конструктор при закодировании
		public RevokedCertificates(params RevokedCertificate[] values) : base(values) {} 
	}
}
