using System;
using System.Runtime.Serialization;

//	EncKeyWithID ::= SEQUENCE {
//		privateKey      PrivateKeyInfo,
//		identifier		Identifier OPTIONAL
//	}

namespace Aladdin.ASN1.ISO.PKCS.PKCS9
{
	[Serializable]
	public class EncKeyWithID : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<PKCS8.PrivateKeyInfo	>().Factory(), Cast.N), 
			new ObjectInfo(new ChoiceCreator<Identifier			    >().Factory(), Cast.O), 
		}; 
		// конструктор при сериализации
        protected EncKeyWithID(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public EncKeyWithID(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public EncKeyWithID(PKCS8.PrivateKeyInfo privateKey, IEncodable identifier) : 
			base(info, privateKey, identifier) {}

		public PKCS8.PrivateKeyInfo	PrivateKey	{ get { return (PKCS8.PrivateKeyInfo)this[0]; } } 
		public IEncodable			Identifier	{ get { return						 this[1]; } }
	}
}
