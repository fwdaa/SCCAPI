using System; 
using System.Runtime.Serialization;

// CRLDistributionPoints ::= SEQUENCE OF DistributionPoint

namespace Aladdin.ASN1.ISO.PKIX.CE
{
	[Serializable]
	public class CrlDistributionPoints : Sequence<DistributionPoint>
	{
		// конструктор при сериализации
        protected CrlDistributionPoints(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public CrlDistributionPoints(IEncodable encodable) : base(encodable) {}

		// конструктор при закодировании
		public CrlDistributionPoints(params DistributionPoint[] values) : base(values) {}
	}
}
