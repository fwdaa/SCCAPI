using System; 

// ExtKeyUsageSyntax ::= SEQUENCE OF OBJECT IDENTIFIER

namespace Aladdin.ASN1.ISO.PKIX.CE
{
	public class ExtKeyUsageSyntax : Sequence<ObjectIdentifier>
	{
		// конструктор при раскодировании
		public ExtKeyUsageSyntax(IEncodable encodable) : base(encodable) {}

		// конструктор при закодировании
		public ExtKeyUsageSyntax(params ObjectIdentifier[] values) : base(values) {}
	}
}
