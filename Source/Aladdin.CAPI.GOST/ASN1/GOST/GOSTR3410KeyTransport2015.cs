using System;

///////////////////////////////////////////////////////////////////////////////
// GostR3410-KeyTransport ::= {
// 	encryptedKey			OCTET STRING,
// 	ephemeralPublicKey		SubjectPublicKeylnfo,
// 	ukm						OCTET STRING
// }
///////////////////////////////////////////////////////////////////////////////
namespace Aladdin.ASN1.GOST
{
	public class GOSTR3410KeyTransport2015 : Sequence 
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<OctetString				  >().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<ISO.PKIX.SubjectPublicKeyInfo>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<OctetString				  >().Factory(), Cast.N)
		}; 
		// конструктор при раскодировании
		public GOSTR3410KeyTransport2015(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public GOSTR3410KeyTransport2015(OctetString encryptedKey, 
			ISO.PKIX.SubjectPublicKeyInfo ephemeralPublicKey, OctetString ukm) : 
			base(info, encryptedKey, ephemeralPublicKey, ukm) {}  

		public OctetString						EncryptedKey		{ get { return (OctetString     				)this[0]; } }
		public ISO.PKIX.SubjectPublicKeyInfo	EphemeralPublicKey	{ get { return (ISO.PKIX.SubjectPublicKeyInfo	)this[1]; } } 
		public OctetString						Ukm					{ get { return (OctetString						)this[2]; } } 
	}
}
