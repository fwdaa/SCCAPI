using System;

//	GOSTR3410TransportParameters ::= SEQUENCE {
//		encryptionParamSet				OBJECT IDENTIFIER,
//		ephemeralPublicKey [0] IMPLICIT SubjectPublicKeyInfo	OPTIONAL,
//		ukm								OCTET STRING ( SIZE(8) )
//	}

namespace Aladdin.ASN1.GOST
{
	public class GOSTR3410TransportParameters : Sequence 
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<ObjectIdentifier				>().Factory(    ), Cast.N,	Tag.Any			), 
			new ObjectInfo(new ObjectCreator<ISO.PKIX.SubjectPublicKeyInfo  >().Factory(    ), Cast.O,	Tag.Context(0)	), 
			new ObjectInfo(new ObjectCreator<OctetString					>().Factory(8, 8), Cast.N,	Tag.Any			), 
		}; 
		// конструктор при раскодировании
		public GOSTR3410TransportParameters(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public GOSTR3410TransportParameters(ObjectIdentifier encryptionParamSet, 
			ISO.PKIX.SubjectPublicKeyInfo ephemeralPublicKey, OctetString ukm) : 
			base(info, encryptionParamSet, ephemeralPublicKey, ukm) {}  

		public ObjectIdentifier					EncryptionParamSet	{ get { return (ObjectIdentifier				)this[0]; } }
		public ISO.PKIX.SubjectPublicKeyInfo	EphemeralPublicKey	{ get { return (ISO.PKIX.SubjectPublicKeyInfo	)this[1]; } } 
		public OctetString						Ukm					{ get { return (OctetString						)this[2]; } } 
	}
}
