using System;
using System.IO;

// Addresses ::= SET OF OCTET STRING 

namespace Aladdin.ASN1.ISO.PKIX.X400
{
	public class Addresses : Set<OctetString>
	{
		// конструктор при раскодировании
		public Addresses(IEncodable encodable) : base(encodable) {}

		// конструктор при закодировании
		public Addresses(params OctetString[] values) : base(values) {}
	}
}
