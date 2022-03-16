using System;
using System.Runtime.Serialization;

//	OtherRecipientInfo ::= SEQUENCE {
//		oriType		OBJECT IDENTIFIER,
//		oriValue	ANY DEFINED BY oriType 
//	}

namespace Aladdin.ASN1.ISO.PKCS.PKCS7
{
	[Serializable]
	public class OtherRecipientInfo : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<ObjectIdentifier>().Factory(), Cast.N), 
			new ObjectInfo(    ImplicitCreator				    .Factory  , Cast.N), 
		}; 
		// конструктор при сериализации
        protected OtherRecipientInfo(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public OtherRecipientInfo(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public OtherRecipientInfo(ObjectIdentifier oriType, IEncodable oriValue) : 
			base(info, oriType, oriValue) {}

		public ObjectIdentifier	OriType		{ get { return (ObjectIdentifier)this[0]; } } 
		public IEncodable		OriValue	{ get { return                   this[1]; } }
	}
}
