using System;
using System.Runtime.Serialization;

//	Attribute ::= SEQUENCE {
//		type	OBJECT IDENTIFIER,
//		values	SET OF ANY DEFINED BY type
//	}

namespace Aladdin.ASN1.ISO
{
	[Serializable]
	public class Attribute : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<ObjectIdentifier	>().Factory(),	Cast.N), 
			new ObjectInfo(new ObjectCreator<Set				>().Factory(),	Cast.N), 
		}; 
		// конструктор при сериализации
        protected Attribute(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public Attribute(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public Attribute(ObjectIdentifier type, Set values) : base(info, type, values) {}

		public ObjectIdentifier Type	{ get { return (ObjectIdentifier)this[0]; } } 
		public Set				Values	{ get { return (Set				)this[1]; } }
	}
}
