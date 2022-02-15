using System;

///////////////////////////////////////////////////////////////////////////////
// Стандарт ГОСТ R34.10-2012
///////////////////////////////////////////////////////////////////////////////
//	GOSTR3410PublicKeyParameters ::= SEQUENCE {
//		publicKeyParamSet	OBJECT IDENTIFIER,
//		digestParamSet		OBJECT IDENTIFIER OPTIONAL
//	}

namespace Aladdin.ASN1.GOST
{
	public class GOSTR3410PublicKeyParameters2012 : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<ObjectIdentifier>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<ObjectIdentifier>().Factory(), Cast.O) 
		}; 
		// конструктор при раскодировании
		public GOSTR3410PublicKeyParameters2012(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public GOSTR3410PublicKeyParameters2012(ObjectIdentifier publicKeyParamSet, 
			ObjectIdentifier digestParamSet) : base(info, publicKeyParamSet, digestParamSet) {}

		public ObjectIdentifier PublicKeyParamSet { get { return (ObjectIdentifier)this[0]; } } 
		public ObjectIdentifier DigestParamSet	  { get { return (ObjectIdentifier)this[1]; } }
    }
}
