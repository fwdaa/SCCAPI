using System;
using System.Runtime.Serialization;

// SafeContents ::= SEQUENCE OF SafeBag

namespace Aladdin.ASN1.ISO.PKCS.PKCS12
{
	[Serializable]
	public class SafeContents : Sequence<SafeBag>
	{
		// конструктор при сериализации
        protected SafeContents(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public SafeContents(IEncodable encodable) : base(encodable) {} 

		// конструктор при закодировании
		public SafeContents(params SafeBag[] values) : base(values) {} 
	}
}
