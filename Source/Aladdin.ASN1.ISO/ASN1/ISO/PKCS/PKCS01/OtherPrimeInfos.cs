using System;

// OtherPrimeInfos ::= SEQUENCE OF OtherPrimeInfo

namespace Aladdin.ASN1.ISO.PKCS.PKCS1
{
	public class OtherPrimeInfos : Sequence<OtherPrimeInfo>
	{
		// конструктор при раскодировании
		public OtherPrimeInfos(IEncodable encodable) : base(encodable) {}

		// конструктор при закодировании
		public OtherPrimeInfos(params OtherPrimeInfo[] values) : base(values) {}
	}
}
