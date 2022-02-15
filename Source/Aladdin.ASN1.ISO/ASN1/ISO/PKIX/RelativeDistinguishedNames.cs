using System;

// RelativeDistinguishedNames ::= SEQUENCE OF RelativeDistinguishedName

namespace Aladdin.ASN1.ISO.PKIX
{
	public class RelativeDistinguishedNames : Sequence<RelativeDistinguishedName>
	{
		// конструктор при раскодировании
		public RelativeDistinguishedNames(IEncodable encodable) : base(encodable) {}

		// конструктор при закодировании
		public RelativeDistinguishedNames(params RelativeDistinguishedName[] values) : base(values) {}
	}
}
