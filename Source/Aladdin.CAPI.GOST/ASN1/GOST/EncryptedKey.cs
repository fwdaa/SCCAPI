using System;

//	GOST28147EncryptedKey ::= SEQUENCE {
//		encryptedKey				OCTET STRING (SIZE (32 | 64)),
//		maskKey      [0] IMPLICIT	OCTET STRING (SIZE (32 | 64)) OPTIONAL,
//		macKey						OCTET STRING (SIZE (4))
//	}

namespace Aladdin.ASN1.GOST
{
	public class EncryptedKey : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<OctetString>().Factory(32, 64), Cast.N, Tag.Any		), 
			new ObjectInfo(new ObjectCreator<OctetString>().Factory(32, 64), Cast.O, Tag.Context(0)	), 
			new ObjectInfo(new ObjectCreator<OctetString>().Factory( 4,  4), Cast.N, Tag.Any		), 
		}; 
		// конструктор при раскодировании
		public EncryptedKey(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public EncryptedKey(OctetString encryptedKey, OctetString maskKey, OctetString macKey) : 
			base(info, encryptedKey, maskKey, macKey) {}

		public OctetString	Encrypted	{ get { return (OctetString)this[0]; } } 
		public OctetString	MaskKey		{ get { return (OctetString)this[1]; } }
		public OctetString	MacKey		{ get { return (OctetString)this[2]; } }
	}
}
