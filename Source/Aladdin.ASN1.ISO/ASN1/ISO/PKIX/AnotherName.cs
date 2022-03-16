using System;
using System.Runtime.Serialization;

//	AnotherName ::= SEQUENCE {
//		type-id    OBJECT IDENTIFIER,
//		value      [0] EXPLICIT ANY DEFINED BY type-id 
//	}

namespace Aladdin.ASN1.ISO.PKIX
{
	[Serializable]
	public class AnotherName : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<ObjectIdentifier>().Factory(), Cast.N, Tag.Any			), 
			new ObjectInfo(    ImplicitCreator				    .Factory  , Cast.E,	Tag.Context(0)  ), 
		}; 
		// конструктор при сериализации
        protected AnotherName(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public AnotherName(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public AnotherName(ObjectIdentifier typeId, IEncodable value) : 
			base(info, typeId, value) {}

		public ObjectIdentifier TypeId	{ get { return (ObjectIdentifier)this[0]; } } 
		public IEncodable		Value	{ get { return                   this[1]; } }
	}
}
