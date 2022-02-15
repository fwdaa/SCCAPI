//	EncryptedKey ::= SEQUENCE {
//      version            INTEGER, 
//		iv                 OCTET STRING (SIZE (8)),
//      spc                OCTET STRING, 
//		encrypted          OCTET STRING OPTIONAL, 
//		ukm                [0] IMPLICIT OCTET STRING (SIZE (8)) OPTIONAL
//	}

namespace Aladdin.ASN1.KZ
{
    public class EncryptedKey  : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<Integer	>().Factory(    ), Cast.N, Tag.Any       ), 
			new ObjectInfo(new ObjectCreator<OctetString>().Factory(8, 8), Cast.N, Tag.Any       ), 
			new ObjectInfo(new ObjectCreator<OctetString>().Factory(    ), Cast.N, Tag.Any       ), 
			new ObjectInfo(new ObjectCreator<OctetString>().Factory(    ), Cast.O, Tag.Any       ), 
			new ObjectInfo(new ObjectCreator<OctetString>().Factory(8, 8), Cast.O, Tag.Context(0)), 
		}; 
		// конструктор при раскодировании
		public EncryptedKey(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public EncryptedKey(Integer version, OctetString iv, 
            OctetString spc, OctetString encrypted, OctetString ukm) 
            : base(info, version, iv, spc, encrypted, ukm) {}  

		public Integer		Version		{ get { return (Integer		)this[0]; } } 
		public OctetString	IV			{ get { return (OctetString	)this[1]; } } 
		public OctetString	Spc			{ get { return (OctetString	)this[2]; } } 
		public OctetString	Encrypted	{ get { return (OctetString	)this[3]; } } 
		public OctetString	UKM	        { get { return (OctetString	)this[4]; } } 
	}
}
