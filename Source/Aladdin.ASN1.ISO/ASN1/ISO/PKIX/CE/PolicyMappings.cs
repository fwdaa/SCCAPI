using System; 

//	PolicyMappings ::= SEQUENCE OF PolicyMapping

namespace Aladdin.ASN1.ISO.PKIX.CE
{
	public class PolicyMappings : Sequence<PolicyMapping>
	{
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
