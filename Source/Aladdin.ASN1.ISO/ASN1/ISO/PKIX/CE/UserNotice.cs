using System; 

// UserNotice ::= SEQUENCE {
//		noticeRef    NoticeReference OPTIONAL,
//		explicitText DisplayText	 OPTIONAL 
//	}

namespace Aladdin.ASN1.ISO.PKIX.CE
{
	public class UserNotice : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<NoticeReference>().Factory(), Cast.O), 
			new ObjectInfo(new ChoiceCreator<DisplayText    >().Factory(), Cast.O), 
		}; 
		// конструктор при раскодировании
		public UserNotice(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public UserNotice(NoticeReference noticeRef, OctetString explicitText) 
			: base(info, noticeRef, explicitText) {} 

		public NoticeReference NoticeRef    { get { return (NoticeReference)this[0]; } } 
		public OctetString     ExplicitText { get { return (OctetString    )this[1]; } }
	}
}
