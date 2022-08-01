using System;
using System.IO;
using System.Runtime.Serialization;

// AuthorityInfoAccessSyntax ::= SEQUENCE SIZE (1..MAX) OF AccessDescription

namespace Aladdin.ASN1.ISO.PKIX.CE
{
	[Serializable]
	public class AuthorityInfoAccessSyntax : Sequence<AccessDescription>
	{
		// конструктор при сериализации
        protected AuthorityInfoAccessSyntax(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public AuthorityInfoAccessSyntax(IEncodable encodable) : base(encodable) 
		{
			// проверить корректность
			if (Length == 0) throw new InvalidDataException(); 
		}
		// конструктор при закодировании
		public AuthorityInfoAccessSyntax(params AccessDescription[] values) : base(values) 
		{
			// проверить корректность
			if (Length == 0) throw new ArgumentException(); 
		}
	}
}
