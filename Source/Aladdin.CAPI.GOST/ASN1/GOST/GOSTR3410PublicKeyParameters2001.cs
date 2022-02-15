using System;

///////////////////////////////////////////////////////////////////////////////
// Стандарт ГОСТ R34.10-2001
///////////////////////////////////////////////////////////////////////////////
//	GOSTR3410PublicKeyParameters ::= SEQUENCE {
//		publicKeyParamSet	OBJECT IDENTIFIER,
//		digestParamSet		OBJECT IDENTIFIER,
//		encryptionParamSet	OBJECT IDENTIFIER	DEFAULT CryptoPro-A-ParamSet
//	}

namespace Aladdin.ASN1.GOST
{
	public class GOSTR3410PublicKeyParameters2001 : Sequence
	{
		// значение идентификатора по умолчанию
		private static readonly ObjectIdentifier def = new ObjectIdentifier(OID.encrypts_A); 

		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<ObjectIdentifier>().Factory(), Cast.N,	Tag.Any		), 
			new ObjectInfo(new ObjectCreator<ObjectIdentifier>().Factory(), Cast.N,	Tag.Any		), 
			new ObjectInfo(new ObjectCreator<ObjectIdentifier>().Factory(), Cast.O,	Tag.Any, def), 
		}; 
		// конструктор при раскодировании
		public GOSTR3410PublicKeyParameters2001(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public GOSTR3410PublicKeyParameters2001(ObjectIdentifier publicKeyParamSet, 
			ObjectIdentifier digestParamSet, ObjectIdentifier encryptionParamSet) : 
			base(info, publicKeyParamSet, digestParamSet, encryptionParamSet) {}

		public ObjectIdentifier PublicKeyParamSet	{ get { return (ObjectIdentifier)this[0]; } } 
		public ObjectIdentifier DigestParamSet		{ get { return (ObjectIdentifier)this[1]; } }
		public ObjectIdentifier EncryptionParamSet	{ get { return (ObjectIdentifier)this[2]; } }
    }
}
