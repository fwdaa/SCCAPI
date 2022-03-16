using System;
using System.Runtime.Serialization; 

//	KeyTransport ::= SEQUENCE {
//		sessionEncryptedKey					GOST28147EncryptedKey,
//		transportParameters [0] IMPLICIT	GOSTR3410TransportParameters OPTIONAL
//	}

namespace Aladdin.ASN1.GOST
{
    [Serializable]
	public class GOSTR3410KeyTransport : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<EncryptedKey		         >().Factory(), Cast.N,	Tag.Any			), 
			new ObjectInfo(new ObjectCreator<GOSTR3410TransportParameters>().Factory(), Cast.O,	Tag.Context(0)	), 
		}; 
		// конструктор при сериализации
        protected GOSTR3410KeyTransport(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public GOSTR3410KeyTransport(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public GOSTR3410KeyTransport(EncryptedKey sessionEncryptedKey, 
			GOSTR3410TransportParameters transportParameters) : 
			base(info, sessionEncryptedKey, transportParameters) {}
  
		public EncryptedKey			SessionEncryptedKey	{ get { return (EncryptedKey		)this[0]; } }
		public GOSTR3410TransportParameters	TransportParameters	{ get { return (GOSTR3410TransportParameters	)this[1]; } } 
	}
}
