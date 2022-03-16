using System; 
using System.Runtime.Serialization;

//	BasicConstraints ::= SEQUENCE {
//		cA                BOOLEAN DEFAULT FALSE,
//		pathLenConstraint INTEGER (0..MAX) OPTIONAL 
//	}

namespace Aladdin.ASN1.ISO.PKIX.CE
{
	[Serializable]
	public class BasicConstraints : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<Boolean>().Factory( ), Cast.O, Tag.Any, Boolean.False), 
			new ObjectInfo(new ObjectCreator<Integer>().Factory(0), Cast.O, Tag.Any				  ), 
		}; 
		// конструктор при сериализации
        protected BasicConstraints(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public BasicConstraints(IEncodable encodable) : base(encodable, info) {} 

		// конструктор при закодировании
		public BasicConstraints(Boolean cA, Integer pathLenConstraint) 
			: base(info, cA, pathLenConstraint) {}

		public Boolean CA				 { get { return (Boolean)this[0]; } } 
		public Integer PathLenConstraint { get { return (Integer)this[1]; } }
	}
}
