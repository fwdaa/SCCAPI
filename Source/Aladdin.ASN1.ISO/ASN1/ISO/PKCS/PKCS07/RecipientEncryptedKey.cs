using System;
using System.Runtime.Serialization;

//	RecipientEncryptedKey ::= SEQUENCE {
//		rid				KeyAgreeRecipientIdentifier,
//		encryptedKey	OCTET STRING
//	}

namespace Aladdin.ASN1.ISO.PKCS.PKCS7
{
	[Serializable]
	public class RecipientEncryptedKey : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ChoiceCreator<KeyAgreeRecipientIdentifier>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<OctetString				>().Factory(), Cast.N), 
		}; 
		// конструктор при сериализации
        protected RecipientEncryptedKey(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public RecipientEncryptedKey(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public RecipientEncryptedKey(IEncodable rid, OctetString encryptedKey) : 
			base(info, rid, encryptedKey) {}

		public IEncodable	Rid				{ get { return				 this[0]; } } 
		public OctetString	EncryptedKey	{ get { return (OctetString )this[1]; } }
	}
}
