using System; 
using System.Runtime.Serialization;

//	PolicyInformation ::= SEQUENCE {
//		policyIdentifier   OBJECT IDENTIFIER,
//		policyQualifiers   PolicyQualifierInfos OPTIONAL 
//	}

namespace Aladdin.ASN1.ISO.PKIX.CE
{
	[Serializable]
	public class PolicyInformation : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<ObjectIdentifier		>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<PolicyQualifierInfos	>().Factory(), Cast.O), 
		}; 
		// конструктор при сериализации
        protected PolicyInformation(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public PolicyInformation(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public PolicyInformation(ObjectIdentifier policyIdentifier, PolicyQualifierInfos policyQualifiers) : 
			base(info, policyIdentifier, policyQualifiers) {}

		public ObjectIdentifier		PolicyIdentifier { get { return (ObjectIdentifier    )this[0]; } } 
		public PolicyQualifierInfos PolicyQualifiers { get { return (PolicyQualifierInfos)this[1]; } }
	}
}
