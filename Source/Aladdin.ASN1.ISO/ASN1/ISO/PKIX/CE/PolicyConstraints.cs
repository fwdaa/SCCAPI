using System; 
using System.Runtime.Serialization;

//	PolicyConstraints ::= SEQUENCE {
//		requireExplicitPolicy   [0] IMPLICIT INTEGER OPTIONAL,
//		inhibitPolicyMapping    [1] IMPLICIT INTEGER OPTIONAL 
//	}

namespace Aladdin.ASN1.ISO.PKIX.CE
{
	[Serializable]
	public class PolicyConstraints : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<Integer>().Factory(0), Cast.O, Tag.Context(0)), 
			new ObjectInfo(new ObjectCreator<Integer>().Factory(0), Cast.O, Tag.Context(1)), 
		}; 
		// конструктор при сериализации
        protected PolicyConstraints(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public PolicyConstraints(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public PolicyConstraints(Integer requireExplicitPolicy, Integer inhibitPolicyMapping) : 
			base(info, requireExplicitPolicy, inhibitPolicyMapping) {}

		public Integer RequireExplicitPolicy { get { return (Integer)this[0]; } } 
		public Integer InhibitPolicyMapping  { get { return (Integer)this[1]; } }
	}
}
