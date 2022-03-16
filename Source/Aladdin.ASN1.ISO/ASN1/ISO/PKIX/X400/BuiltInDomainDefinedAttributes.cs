using System;
using System.IO;
using System.Runtime.Serialization;

// BuiltInDomainDefinedAttributes ::= SEQUENCE SIZE (1..ub-domain-defined-attributes) OF BuiltInDomainDefinedAttribute
// ub-domain-defined-attributes INTEGER ::= 4

namespace Aladdin.ASN1.ISO.PKIX.X400
{
	[Serializable]
	public class BuiltInDomainDefinedAttributes : Sequence<BuiltInDomainDefinedAttribute>
	{
		// конструктор при сериализации
        protected BuiltInDomainDefinedAttributes(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public BuiltInDomainDefinedAttributes(IEncodable encodable) : base(encodable) 
		{ 
			// проверить корректность
			if (Length <= 0 || Length > 4) throw new InvalidDataException(); 
		}
		// конструктор при закодировании
		public BuiltInDomainDefinedAttributes(params BuiltInDomainDefinedAttribute[] values) : base(values) 
		{ 
			// проверить корректность
			if (Length <= 0 || Length > 4) throw new ArgumentException(); 
		} 
		// найти требуемый атрибут
		public BuiltInDomainDefinedAttribute this[string type] { get 
		{
			// для всех атрибутов
			foreach (BuiltInDomainDefinedAttribute attribute in this)
			{
				// проверить совпадение идентификатора
				if (attribute.Type.Value == type) return attribute; 
			}
			return null; 
		}}
	}
}
