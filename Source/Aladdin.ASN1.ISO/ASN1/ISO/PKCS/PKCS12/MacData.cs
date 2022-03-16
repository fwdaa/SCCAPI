using System;
using System.Runtime.Serialization;

//	MacData ::= SEQUENCE {
//		mac			DigestInfo,
//		macSalt		OCTET STRING,
//		iterations	INTEGER			DEFAULT 1
//	}

namespace Aladdin.ASN1.ISO.PKCS.PKCS12
{
	[Serializable]
	public class MacData : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<DigestInfo	>().Factory(), Cast.N,	Tag.Any					), 
			new ObjectInfo(new ObjectCreator<OctetString>().Factory(), Cast.N,	Tag.Any					), 
			new ObjectInfo(new ObjectCreator<Integer	>().Factory(), Cast.O,	Tag.Any,  new Integer(1)), 
		}; 
		// конструктор при сериализации
        protected MacData(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public MacData(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public MacData(DigestInfo mac, OctetString macSalt, Integer iterations) : 
			base(info, mac, macSalt, iterations) {}

		public DigestInfo	Mac			{ get { return (DigestInfo	)this[0]; } } 
		public OctetString	MacSalt		{ get { return (OctetString	)this[1]; } }
		public Integer		Iterations	{ get { return (Integer		)this[2]; } }
	}
}
