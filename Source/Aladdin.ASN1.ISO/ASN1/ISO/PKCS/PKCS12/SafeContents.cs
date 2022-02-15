using System;

// SafeContents ::= SEQUENCE OF SafeBag

namespace Aladdin.ASN1.ISO.PKCS.PKCS12
{
	public class SafeContents : Sequence<SafeBag>
	{
		// конструктор при раскодировании
		public SafeContents(IEncodable encodable) : base(encodable) {} 

		// конструктор при закодировании
		public SafeContents(params SafeBag[] values) : base(values) {} 
	}
}
