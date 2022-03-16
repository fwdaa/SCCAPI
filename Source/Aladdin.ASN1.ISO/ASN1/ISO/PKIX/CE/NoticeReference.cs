using System; 
using System.Runtime.Serialization;

//	NoticeReference ::= SEQUENCE {
//		organization  DisplayText,
//		noticeNumbers SEQUENCE OF INTEGER 
//	}

namespace Aladdin.ASN1.ISO.PKIX.CE
{
	[Serializable]
	public class NoticeReference : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ChoiceCreator<DisplayText      >().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<Sequence<Integer>>().Factory(), Cast.N), 
		}; 
		// конструктор при сериализации
        protected NoticeReference(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public NoticeReference(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public NoticeReference(OctetString organization, Sequence<Integer> noticeNumbers) 
			: base(info, organization, noticeNumbers) {}

		public OctetString			Organization  { get { return (OctetString       )this[0]; } } 
		public Sequence<Integer>	NoticeNumbers { get { return (Sequence<Integer>	)this[1]; } }
	}
}
