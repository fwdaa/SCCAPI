using System;
using System.Runtime.Serialization;

//	KeyTransRecipientInfo ::= SEQUENCE {
//		version					INTEGER,
//		rid						RecipientIdentifier,
//		keyEncryptionAlgorithm	AlgorithmIdentifier,
//		encryptedKey			OCTET STRING 
//	}

namespace Aladdin.ASN1.ISO.PKCS.PKCS7
{
	[Serializable]
	public class KeyTransRecipientInfo : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<Integer			>().Factory(), Cast.N), 
			new ObjectInfo(new ChoiceCreator<RecipientIdentifier>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<AlgorithmIdentifier>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<OctetString		>().Factory(), Cast.N), 
		}; 
		// конструктор при сериализации
        protected KeyTransRecipientInfo(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public KeyTransRecipientInfo(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public KeyTransRecipientInfo(Integer version, IEncodable rid, 
			AlgorithmIdentifier keyEncryptionAlgorithm, OctetString encryptedKey) : 
			base(info, version, rid, keyEncryptionAlgorithm, encryptedKey) {}

		public Integer				Version					{ get { return (Integer				)this[0]; } } 
		public IEncodable			Rid						{ get { return						 this[1]; } }
		public AlgorithmIdentifier	KeyEncryptionAlgorithm	{ get { return (AlgorithmIdentifier	)this[2]; } } 
		public OctetString			EncryptedKey			{ get { return (OctetString			)this[3]; } }
	}
}
