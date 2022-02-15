using System; 

// CRLDistributionPoints ::= SEQUENCE OF DistributionPoint

namespace Aladdin.ASN1.ISO.PKIX.CE
{
	public class CrlDistributionPoints : Sequence<DistributionPoint>
	{
		// конструктор при раскодировании
		public CrlDistributionPoints(IEncodable encodable) : base(encodable) {}

		// конструктор при закодировании
		public CrlDistributionPoints(params DistributionPoint[] values) : base(values) {}
	}
}
