using System;
using System.Runtime.Serialization;

//	KEKIdentifier ::= SEQUENCE {
//		keyIdentifier	OCTET STRING,
//		date			GeneralizedTime		OPTIONAL,
//		other			OtherKeyAttribute	OPTIONAL 
//	}

namespace Aladdin.ASN1.ISO.PKCS.PKCS7
{
	[Serializable]
	public class KEKIdentifier : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<OctetString		>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<GeneralizedTime	>().Factory(), Cast.O), 
			new ObjectInfo(new ObjectCreator<OtherKeyAttribute  >().Factory(), Cast.O), 
		}; 
		// конструктор при сериализации
        protected KEKIdentifier(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public KEKIdentifier(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public KEKIdentifier(OctetString keyIdentifier, GeneralizedTime date, 
			OtherKeyAttribute other) : base(info, keyIdentifier, date, other) {}

		public OctetString			KeyIdentifier	{ get { return (OctetString			)this[0]; } } 
		public GeneralizedTime		Date			{ get { return (GeneralizedTime		)this[1]; } }
		public OtherKeyAttribute	Other			{ get { return (OtherKeyAttribute	)this[2]; } } 
	}
}
