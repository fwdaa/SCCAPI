using System;

// KeySpecificInfo ::= SEQUENCE {
//		algorithm	OBJECT IDENTIFIER,
//		counter		OCTET STRING SIZE (4..4) 
//	}

namespace Aladdin.ASN1.ANSI.X942
{
	public class KeySpecificInfo : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<ObjectIdentifier>().Factory(    ), Cast.N), 
			new ObjectInfo(new ObjectCreator<OctetString     >().Factory(4, 4), Cast.N), 
		}; 
		// конструктор при раскодировании
		public KeySpecificInfo(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public KeySpecificInfo(ObjectIdentifier algorithm, OctetString counter) : 
			base(info, algorithm, counter) {}

		public ObjectIdentifier Algorithm	{ get { return (ObjectIdentifier)this[0]; } } 
		public OctetString		Counter		{ get { return (OctetString     )this[1]; } }
	}
}
