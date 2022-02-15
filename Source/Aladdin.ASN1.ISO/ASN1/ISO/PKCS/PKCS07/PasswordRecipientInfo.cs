using System;

//	PasswordRecipientInfo ::= SEQUENCE {
//		version								INTEGER,
//		keyDerivationAlgorithm [0] IMPLICIT AlgorithmIdentifier OPTIONAL,
//		keyEncryptionAlgorithm				AlgorithmIdentifier,
//		encryptedKey						OCTET STRING 
//	}

namespace Aladdin.ASN1.ISO.PKCS.PKCS7
{
	public class PasswordRecipientInfo : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<Integer			>().Factory(), Cast.N,	Tag.Any			), 
			new ObjectInfo(new ObjectCreator<AlgorithmIdentifier>().Factory(), Cast.O,	Tag.Context(0)	), 
			new ObjectInfo(new ObjectCreator<AlgorithmIdentifier>().Factory(), Cast.N,	Tag.Any			), 
			new ObjectInfo(new ObjectCreator<OctetString		>().Factory(), Cast.N,	Tag.Any			), 
		}; 
		// конструктор при раскодировании
		public PasswordRecipientInfo(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public PasswordRecipientInfo(Integer version, 
			AlgorithmIdentifier keyDerivationAlgorithm, 
			AlgorithmIdentifier keyEncryptionAlgorithm, OctetString encryptedKey) : 
			base(info, version, keyDerivationAlgorithm, keyEncryptionAlgorithm, encryptedKey) {}

		public Integer				Version					{ get { return (Integer				)this[0]; } } 
		public AlgorithmIdentifier	KeyDerivationAlgorithm	{ get { return (AlgorithmIdentifier	)this[1]; } }
		public AlgorithmIdentifier	KeyEncryptionAlgorithm	{ get { return (AlgorithmIdentifier	)this[2]; } }
		public OctetString			EncryptedKey			{ get { return (OctetString			)this[3]; } } 
	}
}
