using System;
using System.Runtime.Serialization;

//	KeyAgreeRecipientInfo ::= SEQUENCE {
//		version									INTEGER,
//		originator				[0] EXPLICIT	OriginatorIdentifierOrKey,
//		ukm						[1] EXPLICIT	OCTET STRING			OPTIONAL,
//		keyEncryptionAlgorithm					AlgorithmIdentifier,
//		recipientEncryptedKeys					RecipientEncryptedKeys 
//	}

namespace Aladdin.ASN1.ISO.PKCS.PKCS7
{
	[Serializable]
	public class KeyAgreeRecipientInfo : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<Integer					>().Factory(), Cast.N,	Tag.Any			), 
			new ObjectInfo(new ChoiceCreator<OriginatorIdentifierOrKey  >().Factory(), Cast.E,	Tag.Context(0)	), 
			new ObjectInfo(new ObjectCreator<OctetString				>().Factory(), Cast.EO,	Tag.Context(1)	), 
			new ObjectInfo(new ObjectCreator<AlgorithmIdentifier		>().Factory(), Cast.N,	Tag.Any			), 
			new ObjectInfo(new ObjectCreator<RecipientEncryptedKeys	    >().Factory(), Cast.N,	Tag.Any			), 
		}; 
		// конструктор при сериализации
        protected KeyAgreeRecipientInfo(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public KeyAgreeRecipientInfo(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public KeyAgreeRecipientInfo(Integer version, IEncodable originator, 
			OctetString ukm, AlgorithmIdentifier keyEncryptionAlgorithm, 
			RecipientEncryptedKeys recipientEncryptedKeys) : 
			base(info, version, originator, ukm, keyEncryptionAlgorithm, recipientEncryptedKeys) {}

		public Integer					Version					{ get { return (Integer					)this[0]; } } 
		public IEncodable				Originator				{ get { return							 this[1]; } }
		public OctetString				Ukm						{ get { return (OctetString				)this[2]; } } 
		public AlgorithmIdentifier		KeyEncryptionAlgorithm	{ get { return (AlgorithmIdentifier		)this[3]; } }
		public RecipientEncryptedKeys	RecipientEncryptedKeys	{ get { return (RecipientEncryptedKeys	)this[4]; } }
	}
}
