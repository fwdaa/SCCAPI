using System;
using System.Runtime.Serialization;

//	AttrributeGeneralNames ::= SEQUENCE {
//		issuerName						GeneralNames		OPTIONAL,
//		baseCertificateID [0] IMPLICIT	IssuerSerial		OPTIONAL,
//		objectDigestInfo  [1] IMPLICIT	ObjectDigestInfo	OPTIONAL
//}

namespace Aladdin.ASN1.ISO.PKIX
{
	[Serializable]
	public class AttrributeGeneralNames : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<GeneralNames		>().Factory(), Cast.O,	Tag.Any			), 
			new ObjectInfo(new ObjectCreator<IssuerSerial		>().Factory(), Cast.O,	Tag.Context(0)	), 
			new ObjectInfo(new ObjectCreator<ObjectDigestInfo	>().Factory(), Cast.O,	Tag.Context(1)	), 
		}; 
		// конструктор при сериализации
        protected AttrributeGeneralNames(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public AttrributeGeneralNames(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public AttrributeGeneralNames(GeneralNames issuerName, IssuerSerial baseCertificateID, 
			ObjectDigestInfo objectDigestInfo) : 
			base(info, issuerName, baseCertificateID, objectDigestInfo) {}

		public GeneralNames		IssuerName			{ get { return (GeneralNames	)this[0]; } }
		public IssuerSerial		BaseCertificateID	{ get { return (IssuerSerial	)this[1]; } } 
		public ObjectDigestInfo	ObjectDigestInfo	{ get { return (ObjectDigestInfo)this[2]; } }
	}
}
