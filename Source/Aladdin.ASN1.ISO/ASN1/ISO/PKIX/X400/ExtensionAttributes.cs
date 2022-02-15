using System;
using System.IO;

// ExtensionAttributes ::= SET SIZE (1..ub-extension-attributes) OF ExtensionAttribute
// ub-extension-attributes INTEGER ::= 256

namespace Aladdin.ASN1.ISO.PKIX.X400
{
	public class ExtensionAttributes : Set<ExtensionAttribute>
	{
		// конструктор при раскодировании
		public ExtensionAttributes(IEncodable encodable) : base(encodable) 
		{ 
			// проверить корректность
			if (Length <= 0 || Length > 256) throw new InvalidDataException(); 
		}
		// конструктор при закодировании
		public ExtensionAttributes(params ExtensionAttribute[] values) : base(values) 
		{ 
			// проверить корректность
			if (Length <= 0 || Length > 256) throw new ArgumentException(); 
		}
		public new ExtensionAttribute this[int type] { get 
		{
			// для всех атрибутов
			foreach (ExtensionAttribute attribute in this)
			{
				// проверить совпадение идентификатора
				if (attribute.ExtensionAttributeType.Value.IntValue == type) return attribute; 
			}
			return null; 
		}}
	}
}
