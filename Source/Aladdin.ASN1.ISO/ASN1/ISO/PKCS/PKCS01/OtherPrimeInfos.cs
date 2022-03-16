using System;
using System.Runtime.Serialization;

// OtherPrimeInfos ::= SEQUENCE OF OtherPrimeInfo

namespace Aladdin.ASN1.ISO.PKCS.PKCS1
{
	[Serializable]
	public class OtherPrimeInfos : Sequence<OtherPrimeInfo>
	{
		// конструктор при сериализации
        protected OtherPrimeInfos(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public OtherPrimeInfos(IEncodable encodable) : base(encodable) {}

		// конструктор при закодировании
		public OtherPrimeInfos(params OtherPrimeInfo[] values) : base(values) {}
	}
}
