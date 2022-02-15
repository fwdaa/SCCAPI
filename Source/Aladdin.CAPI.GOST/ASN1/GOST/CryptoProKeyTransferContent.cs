using System;

//	KeyTransferContent ::= SEQUENCE {
//		seanceVector			OCTET STRING (8),
//		encryptedPrivateKey 	GOST28147EncryptedKey, 
//		privateKeyParameters	[0] IMPLICIT GOSTPrivateKeyParameters OPTIONAL, 
//	}

namespace Aladdin.ASN1.GOST
{
	public class CryptoProKeyTransferContent : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<OctetString			      >().Factory(), Cast.N,	Tag.Any			), 
			new ObjectInfo(new ObjectCreator<EncryptedKey			      >().Factory(), Cast.N,	Tag.Any			), 
			new ObjectInfo(new ObjectCreator<CryptoProPrivateKeyParameters>().Factory(), Cast.O,	Tag.Context(0)	), 
		}; 
		// конструктор при раскодировании
		public CryptoProKeyTransferContent(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public CryptoProKeyTransferContent(OctetString seanceVector, EncryptedKey encryptedPrivateKey, 
			CryptoProPrivateKeyParameters privateKeyParameters) : 
			base(info, seanceVector, encryptedPrivateKey, privateKeyParameters) {}
  
		public OctetString						SeanceVector			{ get { return (OctetString					 )this[0]; } }
		public EncryptedKey						EncryptedPrivateKey		{ get { return (EncryptedKey				 )this[1]; } }
		public CryptoProPrivateKeyParameters	PrivateKeyParameters	{ get { return (CryptoProPrivateKeyParameters)this[2]; } }
	}
}
