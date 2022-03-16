using System;
using System.Runtime.Serialization;

//	EDIPartyName ::= SEQUENCE {
//		nameAssigner [0] IMPLICIT DirectoryString OPTIONAL,
//		partyName    [1] IMPLICIT DirectoryString 
//	}

namespace Aladdin.ASN1.ISO.PKIX
{
	[Serializable]
	public class EDIPartyName : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ChoiceCreator<DirectoryString>().Factory(), Cast.O, Tag.Context(0)), 
			new ObjectInfo(new ChoiceCreator<DirectoryString>().Factory(), Cast.N, Tag.Context(1)), 
		}; 
		// конструктор при сериализации
        protected EDIPartyName(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public EDIPartyName(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public EDIPartyName(OctetString nameAssigner, OctetString partyName) : 
			base(info, nameAssigner, partyName) {}

		public OctetString NameAssigner	{ get { return (OctetString)this[0]; } } 
		public OctetString PartyName	{ get { return (OctetString)this[1]; } }
	}
}
