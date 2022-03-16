using System;
using System.Runtime.Serialization;

// AuthenticatedSafe ::= SEQUENCE OF ContentInfo

namespace Aladdin.ASN1.ISO.PKCS.PKCS12
{
	[Serializable]
	public class AuthenticatedSafe : Sequence<ContentInfo>
	{
		// конструктор при сериализации
        protected AuthenticatedSafe(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public AuthenticatedSafe(IEncodable encodable) : base(encodable) {} 

		// конструктор при закодировании
		public AuthenticatedSafe(params ContentInfo[] values) : base(values) {} 
	}
}
