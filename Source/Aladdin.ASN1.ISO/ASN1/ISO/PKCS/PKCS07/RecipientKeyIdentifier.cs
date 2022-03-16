using System;
using System.Runtime.Serialization;

//	RecipientKeyIdentifier ::= SEQUENCE {
//		subjectKeyIdentifier	OCTET STRING,
//		date					GeneralizedTime			OPTIONAL,
//		other					OtherKeyAttribute		OPTIONAL 
//	}

namespace Aladdin.ASN1.ISO.PKCS.PKCS7
{
	[Serializable]
	public class RecipientKeyIdentifier : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<OctetString		>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<GeneralizedTime	>().Factory(), Cast.O), 
			new ObjectInfo(new ObjectCreator<OtherKeyAttribute  >().Factory(), Cast.O), 
		}; 
		// конструктор при сериализации
        protected RecipientKeyIdentifier(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public RecipientKeyIdentifier(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public RecipientKeyIdentifier(OctetString subjectKeyIdentifier, 
			GeneralizedTime date, OtherKeyAttribute other) : 
			base(info, subjectKeyIdentifier, date, other) {}

		public OctetString			SubjectKeyIdentifier	{ get { return (OctetString			)this[0]; } } 
		public GeneralizedTime		Date					{ get { return (GeneralizedTime		)this[1]; } }
		public OtherKeyAttribute	Other					{ get { return (OtherKeyAttribute	)this[2]; } } 
	}
}
