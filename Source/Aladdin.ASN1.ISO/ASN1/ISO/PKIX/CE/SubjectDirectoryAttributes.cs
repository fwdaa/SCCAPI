using System; 
using System.Runtime.Serialization;

// SubjectDirectoryAttributes ::= SEQUENCE OF Attribute

namespace Aladdin.ASN1.ISO.PKIX.CE
{
	[Serializable]
	public class SubjectDirectoryAttributes : Sequence<Attribute>
	{
		// конструктор при сериализации
        protected SubjectDirectoryAttributes(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public SubjectDirectoryAttributes(IEncodable encodable) : base(encodable) {}

		// конструктор при закодировании
		public SubjectDirectoryAttributes(params Attribute[] values) : base(values) {}
	
		// найти требуемый атрибут
		public Attribute this[string oid] { get 
		{
			// для всех атрибутов
			foreach (Attribute attribute in this)
			{
				// проверить совпадение идентификатора
				if (attribute.Type.Value == oid) return attribute; 
			}
			return null; 
		}}
	}
}
