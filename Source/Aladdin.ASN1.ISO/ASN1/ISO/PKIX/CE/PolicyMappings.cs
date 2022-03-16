using System; 
using System.Runtime.Serialization;

//	PolicyMappings ::= SEQUENCE OF PolicyMapping

namespace Aladdin.ASN1.ISO.PKIX.CE
{
	[Serializable]
	public class PolicyMappings : Sequence<PolicyMapping>
	{
		// конструктор при сериализации
        protected PolicyMappings(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public PolicyMappings(IEncodable encodable) : base(encodable) {}

		// конструктор при закодировании
		public PolicyMappings(params PolicyMapping[] values) : base(values) {}

		// найти требуемый атрибут
		public PolicyMapping this[string oid] { get 
		{
			// для всех атрибутов
			foreach (PolicyMapping mapping in this)
			{
				// проверить совпадение идентификатора
				if (mapping.IssuerDomainPolicy.Value == oid) return mapping; 
			}
			return null; 
		}}
	}
}
