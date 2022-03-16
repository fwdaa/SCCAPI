using System; 
using System.Runtime.Serialization;

// GeneralSubtrees ::= SEQUENCE OF GeneralSubtree

namespace Aladdin.ASN1.ISO.PKIX.CE
{
	[Serializable]
	public class GeneralSubtrees : Sequence<GeneralSubtree>
	{
		// конструктор при сериализации
        protected GeneralSubtrees(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public GeneralSubtrees(IEncodable encodable) : base(encodable) {}

		// конструктор при закодировании
		public GeneralSubtrees(params GeneralSubtree[] values) : base(values) {}
	}
}
