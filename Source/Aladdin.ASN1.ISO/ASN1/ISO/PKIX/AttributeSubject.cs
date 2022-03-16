using System;
using System.Runtime.Serialization;

//	AttributeSubject ::= SEQUENCE {
//		baseCertificateID   [0] IMPLICIT IssuerSerial OPTIONAL,
//		entityName          [1] IMPLICIT GeneralNames OPTIONAL,
//		objectDigestInfo    [2] IMPLICIT ObjectDigestInfo OPTIONAL
//	}

namespace Aladdin.ASN1.ISO.PKIX
{
	[Serializable]
	public class AttributeSubject : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<IssuerSerial		>().Factory(), Cast.O, Tag.Context(0)), 
			new ObjectInfo(new ObjectCreator<GeneralNames		>().Factory(), Cast.O, Tag.Context(1)), 
			new ObjectInfo(new ObjectCreator<ObjectDigestInfo	>().Factory(), Cast.O, Tag.Context(2)), 
		}; 
		// конструктор при сериализации
        protected AttributeSubject(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public AttributeSubject(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public AttributeSubject(IssuerSerial baseCertificateID, GeneralNames entityName, 
			ObjectDigestInfo objectDigestInfo) : 
			base(info, baseCertificateID, entityName, objectDigestInfo) {}

		public IssuerSerial		BaseCertificateID	{ get { return (IssuerSerial	)this[0]; } } 
		public GeneralNames		EntityName			{ get { return (GeneralNames	)this[1]; } }
		public ObjectDigestInfo	ObjectDigestInfo	{ get { return (ObjectDigestInfo)this[2]; } }
	}
}
