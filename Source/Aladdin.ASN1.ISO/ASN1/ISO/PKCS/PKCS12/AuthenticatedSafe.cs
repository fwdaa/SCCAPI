using System;

// AuthenticatedSafe ::= SEQUENCE OF ContentInfo

namespace Aladdin.ASN1.ISO.PKCS.PKCS12
{
	public class AuthenticatedSafe : Sequence<ContentInfo>
	{
		// конструктор при раскодировании
		public AuthenticatedSafe(IEncodable encodable) : base(encodable) {} 

		// конструктор при закодировании
		public AuthenticatedSafe(params ContentInfo[] values) : base(values) {} 
	}
}
