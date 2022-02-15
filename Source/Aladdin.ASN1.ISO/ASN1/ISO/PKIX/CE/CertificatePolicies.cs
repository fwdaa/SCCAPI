using System; 

// CertificatePolicies ::= SEQUENCE OF PolicyInformation

namespace Aladdin.ASN1.ISO.PKIX.CE
{
	public class CertificatePolicies : Sequence<PolicyInformation>
	{
		// конструктор при раскодировании
		public CertificatePolicies(IEncodable encodable) : base(encodable) {} 

		// конструктор при закодировании
		public CertificatePolicies(params PolicyInformation[] values) : base(values) {}

		// найти требуемый атрибут
		public PolicyInformation this[string oid] { get 
		{
			// для всех атрибутов
			foreach (PolicyInformation information in this)
			{
				// проверить совпадение идентификатора
				if (information.PolicyIdentifier.Value == oid) return information; 
			}
			return null; 
		}}
	}
}
