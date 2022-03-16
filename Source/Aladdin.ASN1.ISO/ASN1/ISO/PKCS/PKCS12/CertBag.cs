using System;
using System.Runtime.Serialization;

//	CertBag ::= SEQUENCE {
//		certId						OBJECT IDENTIFIER,
//		certValue	[0] EXPLICIT	ANY DEFINED BY certId
//	}

namespace Aladdin.ASN1.ISO.PKCS.PKCS12
{
	[Serializable]
	public class CertBag : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<ObjectIdentifier>().Factory(), Cast.N,	Tag.Any			), 
			new ObjectInfo(    ImplicitCreator				    .Factory  , Cast.E,	Tag.Context(0)	), 
		}; 
		// конструктор при сериализации
        protected CertBag(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public CertBag(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public CertBag(ObjectIdentifier certId, IEncodable certValue) : 
			base(info, certId, certValue) {}

		public ObjectIdentifier	CertId		{ get { return (ObjectIdentifier)this[0]; } } 
		public IEncodable		CertValue	{ get { return					 this[1]; } }
	}
}
