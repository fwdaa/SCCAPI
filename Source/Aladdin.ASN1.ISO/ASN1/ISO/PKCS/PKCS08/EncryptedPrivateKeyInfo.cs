using System;
using System.Runtime.Serialization;

//	EncryptedPrivateKeyInfo ::= SEQUENCE {
//		encryptionAlgorithm	AlgorithmIdentifier,
//		encryptedData		OCTET STRING
//	}

namespace Aladdin.ASN1.ISO.PKCS.PKCS8
{
	[Serializable]
	public class EncryptedPrivateKeyInfo : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<AlgorithmIdentifier>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<OctetString		>().Factory(), Cast.N), 
		}; 
		// конструктор при сериализации
        protected EncryptedPrivateKeyInfo(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public EncryptedPrivateKeyInfo(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public EncryptedPrivateKeyInfo(AlgorithmIdentifier encryptionAlgorithm, 
			OctetString encryptedData) : base(info, encryptionAlgorithm, encryptedData) {}

		public AlgorithmIdentifier	EncryptionAlgorithm	{ get { return (AlgorithmIdentifier	)this[0]; } } 
		public OctetString			EncryptedData		{ get { return (OctetString			)this[1]; } }
	}
}
