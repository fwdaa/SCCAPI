using System;

//	AttributeTypeValue ::= SEQUENCE {
//		type    OBJECT IDENTIFIER,
//		value   ANY DEFINED BY type
//	}
namespace Aladdin.ASN1.ISO.PKIX
{
	public class AttributeTypeValue : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<ObjectIdentifier>().Factory(), Cast.N, Tag.Any), 
			new ObjectInfo(    ImplicitCreator				    .Factory  , Cast.N, Tag.Any), 
		}; 
		// конструктор при раскодировании
		public AttributeTypeValue(IEncodable encodable) : base(encodable, info) {}
		
		// конструктор при закодировании
		public AttributeTypeValue(ObjectIdentifier type, IEncodable value) : 
			base(info, type, value) {}

		public ObjectIdentifier Type	{ get { return (ObjectIdentifier)this[0]; } } 
		public IEncodable		Value	{ get { return					 this[1]; } }
	}
}
