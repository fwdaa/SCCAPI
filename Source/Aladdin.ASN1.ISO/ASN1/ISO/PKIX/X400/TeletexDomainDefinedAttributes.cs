using System;
using System.IO;
using System.Runtime.Serialization;

// TeletexDomainDefinedAttributes ::= SEQUENCE SIZE (1..ub-domain-defined-attributes) OF TeletexDomainDefinedAttribute
// ub-domain-defined-attributes INTEGER ::= 4

namespace Aladdin.ASN1.ISO.PKIX.X400
{
	[Serializable]
	public class TeletexDomainDefinedAttributes : Sequence<TeletexDomainDefinedAttribute>
	{
		// конструктор при сериализации
        protected TeletexDomainDefinedAttributes(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public TeletexDomainDefinedAttributes(IEncodable encodable) : base(encodable) 
		{ 
			// проверить корректность
			if (Length <= 0 || Length > 4) throw new InvalidDataException(); 
		}
		// конструктор при закодировании
		public TeletexDomainDefinedAttributes(params TeletexDomainDefinedAttribute[] values) : base(values) 
		{ 
			// проверить корректность
			if (Length <= 0 || Length > 4) throw new ArgumentException(); 
		}
	}
}
