using System;
using System.IO;
using System.Runtime.Serialization;

// SubjectInfoAccessSyntax ::= SEQUENCE SIZE (1..MAX) OF AccessDescription

namespace Aladdin.ASN1.ISO.PKIX.CE
{
	[Serializable]
	public class SubjectInfoAccessSyntax : Sequence<AccessDescription>
	{
		// конструктор при сериализации
        protected SubjectInfoAccessSyntax(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public SubjectInfoAccessSyntax(IEncodable encodable) : base(encodable) 
		{
			// проверить корректность
			if (Length == 0) throw new InvalidDataException(); 
		}
		// конструктор при закодировании
		public SubjectInfoAccessSyntax(params AccessDescription[] values) : base(values) 
		{
			// проверить корректность
			if (Length == 0) throw new ArgumentException(); 
		}
	}
}
