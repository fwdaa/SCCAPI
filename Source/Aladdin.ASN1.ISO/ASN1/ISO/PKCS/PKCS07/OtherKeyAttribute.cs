using System;
using System.Runtime.Serialization;

//	OtherKeyAttribute ::= SEQUENCE {
//		keyAttrId	OBJECT IDENTIFIER,
//		keyAttr		ANY DEFINED BY keyAttrId OPTIONAL 
//	}

namespace Aladdin.ASN1.ISO.PKCS.PKCS7
{
	[Serializable]
	public class OtherKeyAttribute : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<ObjectIdentifier>().Factory(), Cast.N), 
			new ObjectInfo(    ImplicitCreator				    .Factory  , Cast.O), 
		}; 
		// конструктор при сериализации
        protected OtherKeyAttribute(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public OtherKeyAttribute(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public OtherKeyAttribute(ObjectIdentifier keyAttrId, IEncodable keyAttr) : 
			base(info, keyAttrId, keyAttr) {}

		public ObjectIdentifier	KeyAttrId	{ get { return (ObjectIdentifier)this[0]; } } 
		public IEncodable		KeyAttr		{ get { return                   this[1]; } }
	}
}
