using System; 

// PolicyQualifierInfos ::= SEQUENCE OF PolicyQualifierInfo

namespace Aladdin.ASN1.ISO.PKIX.CE
{
	public class PolicyQualifierInfos : Sequence<PolicyQualifierInfo>
	{
		// конструктор при раскодировании
		public PolicyQualifierInfos(IEncodable encodable) : base(encodable) {}

		// конструктор при закодировании
		public PolicyQualifierInfos(params PolicyQualifierInfo[] values) : base(values) {}

		// найти требуемый атрибут
		public PolicyQualifierInfo this[string oid] { get 
		{
			// для всех атрибутов
			foreach (PolicyQualifierInfo info in this)
			{
				// проверить совпадение идентификатора
				if (info.PolicyQualifierId.Value == oid) return info; 
			}
			return null; 
		}}
	}
}
