using System; 

// GeneralSubtrees ::= SEQUENCE OF GeneralSubtree

namespace Aladdin.ASN1.ISO.PKIX.CE
{
	public class GeneralSubtrees : Sequence<GeneralSubtree>
	{
		// конструктор при раскодировании
		public GeneralSubtrees(IEncodable encodable) : base(encodable) {}

		// конструктор при закодировании
		public GeneralSubtrees(params GeneralSubtree[] values) : base(values) {}
	}
}
