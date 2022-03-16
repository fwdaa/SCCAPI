using System;
using System.Runtime.Serialization;

//	CRLBag ::= SEQUENCE {
//		crlId			         OBJECT IDENTIFIER,
//		crltValue	[0] EXPLICIT ANY DEFINED BY crlId
//	}

namespace Aladdin.ASN1.ISO.PKCS.PKCS12
{
	[Serializable]
	public class CRLBag : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<ObjectIdentifier>().Factory(), Cast.N,	Tag.Any			), 
			new ObjectInfo(    ImplicitCreator				    .Factory  , Cast.E,	Tag.Context(0)	), 
		}; 
		// конструктор при сериализации
        protected CRLBag(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public CRLBag(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public CRLBag(ObjectIdentifier crlId, IEncodable crltValue) : 
			base(info, crlId, crltValue) {}

		public ObjectIdentifier	CrlId		{ get { return (ObjectIdentifier)this[0]; } } 
		public IEncodable		CrltValue	{ get { return					 this[1]; } }
	}
}
