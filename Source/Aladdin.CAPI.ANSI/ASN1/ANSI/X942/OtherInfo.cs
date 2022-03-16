using System;
using System.Runtime.Serialization;

// OtherInfo ::= SEQUENCE {
//	keyInfo		KeySpecificInfo,
//	partyAInfo	[0] EXPLICIT OCTET STRING OPTIONAL,
//	suppPubInfo [2] EXPLICIT OCTET STRING
// }

namespace Aladdin.ASN1.ANSI.X942
{
	[Serializable]
	public class OtherInfo : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<KeySpecificInfo >().Factory(), Cast.N , Tag.Any		), 
			new ObjectInfo(new ObjectCreator<OctetString     >().Factory(), Cast.EO, Tag.Context(0)	), 
			new ObjectInfo(new ObjectCreator<OctetString     >().Factory(), Cast.E , Tag.Context(2)	) 
		}; 
		// конструктор при сериализации
        protected OtherInfo(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public OtherInfo(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public OtherInfo(KeySpecificInfo keyInfo, OctetString partyAInfo, 
			OctetString suppPubInfo) : base(info, keyInfo, partyAInfo, suppPubInfo) {}  

		public KeySpecificInfo KeyInfo		{ get { return (KeySpecificInfo)this[0]; } } 
		public OctetString	   PartyAInfo	{ get { return (OctetString    )this[1]; } }
		public OctetString	   SuppPubInfo	{ get { return (OctetString    )this[2]; } }
	}
}
