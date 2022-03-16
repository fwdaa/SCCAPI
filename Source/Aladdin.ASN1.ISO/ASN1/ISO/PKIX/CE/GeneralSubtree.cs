using System; 
using System.Runtime.Serialization;

//	GeneralSubtree ::= SEQUENCE {
//		base                 GeneralName,
//		minimum [0] IMPLICIT INTEGER (0..MAX) DEFAULT 0,
//		maximum [1] IMPLICIT INTEGER (0..MAX) OPTIONAL 
//	}

namespace Aladdin.ASN1.ISO.PKIX.CE
{
	[Serializable]
	public class GeneralSubtree : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ChoiceCreator<GeneralName>().Factory( ), Cast.N, Tag.Any			), 
			new ObjectInfo(new ObjectCreator<Integer	>().Factory(0), Cast.O, Tag.Context(0)	), 
			new ObjectInfo(new ObjectCreator<Integer	>().Factory(0), Cast.O, Tag.Context(1)	), 
		}; 
		// конструктор при сериализации
        protected GeneralSubtree(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public GeneralSubtree(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public GeneralSubtree(IEncodable based, Integer minimum, Integer maximum) : 
			base(info, based, minimum, maximum) {}

		public IEncodable	Base    { get { return			this[0]; } } 
		public Integer		Minimum { get { return (Integer)this[1]; } }
		public Integer		Maximum { get { return (Integer)this[2]; } }
	}
}
