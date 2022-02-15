using System;

// RelativeDistinguishedName ::= SET OF AttributeTypeValue

namespace Aladdin.ASN1.ISO.PKIX
{
	public class RelativeDistinguishedName : Set<AttributeTypeValue>
	{
		// конструктор при раскодировании
		public RelativeDistinguishedName(IEncodable encodable) : base(encodable) {}

		// конструктор при закодировании
		public RelativeDistinguishedName(params AttributeTypeValue[] values) : base(values) {}
	
		// найти требуемый атрибут
		public AttributeTypeValue this[string oid] { get 
		{
			// для всех атрибутов
			foreach (AttributeTypeValue attribute in this)
			{
				// проверить совпадение идентификатора
				if (attribute.Type.Value == oid) return attribute; 
			}
			return null; 
		}}
	}
}
