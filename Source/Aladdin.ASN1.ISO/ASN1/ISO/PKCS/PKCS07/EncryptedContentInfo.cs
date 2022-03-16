using System;
using System.Runtime.Serialization;

//	EncryptedContentInfo ::= SEQUENCE {
//		contentType									OBJECT IDENTIFIER,
//		contentEncryptionAlgorithm					AlgorithmIdentifier,
//		encryptedContent			[0] IMPLICIT	OCTET STRING	OPTIONAL 
//	}

namespace Aladdin.ASN1.ISO.PKCS.PKCS7
{
	[Serializable]
	public class EncryptedContentInfo : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<ObjectIdentifier	>().Factory(), Cast.N,	Tag.Any			), 
			new ObjectInfo(new ObjectCreator<AlgorithmIdentifier>().Factory(), Cast.N,	Tag.Any			), 
			new ObjectInfo(new ObjectCreator<OctetString		>().Factory(), Cast.O,	Tag.Context(0)	), 
		}; 
		// конструктор при сериализации
        protected EncryptedContentInfo(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public EncryptedContentInfo(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public EncryptedContentInfo(ObjectIdentifier contentType, 
            AlgorithmIdentifier contentEncryptionAlgorithm, OctetString encryptedContent) 
                : base(info, contentType, contentEncryptionAlgorithm, encryptedContent) {}

		public ObjectIdentifier		ContentType					{ get { return (ObjectIdentifier	)this[0]; } } 
		public AlgorithmIdentifier	ContentEncryptionAlgorithm	{ get { return (AlgorithmIdentifier	)this[1]; } }
		public OctetString			EncryptedContent			{ get { return (OctetString			)this[2]; } }
	}
}
