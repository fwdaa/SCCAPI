using System;
using System.Runtime.Serialization;

//	KEKRecipientInfo ::= SEQUENCE {
//		version					INTEGER,
//		kekid					KEKIdentifier,
//		keyEncryptionAlgorithm	AlgorithmIdentifier,
//		encryptedKey			OCTET STRING 
//	}

namespace Aladdin.ASN1.ISO.PKCS.PKCS7
{
	[Serializable]
	public class KEKRecipientInfo : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<Integer			>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<KEKIdentifier		>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<AlgorithmIdentifier>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<OctetString		>().Factory(), Cast.N), 
		}; 
		// конструктор при сериализации
        protected KEKRecipientInfo(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public KEKRecipientInfo(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public KEKRecipientInfo(Integer version, KEKIdentifier kekid, 
			AlgorithmIdentifier keyEncryptionAlgorithm, OctetString encryptedKey) : 
			base(info, version, kekid, keyEncryptionAlgorithm, encryptedKey) {}

		public Integer				Version					{ get { return (Integer				)this[0]; } } 
		public KEKIdentifier		Kekid					{ get { return (KEKIdentifier		)this[1]; } }
		public AlgorithmIdentifier	KeyEncryptionAlgorithm	{ get { return (AlgorithmIdentifier	)this[2]; } }
		public OctetString			EncryptedKey			{ get { return (OctetString			)this[3]; } } 
	}
}
