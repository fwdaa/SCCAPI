package aladdin.asn1.iso.pkix.ce;
import aladdin.asn1.*; 
import java.io.*; 

// UserNotice ::= SEQUENCE {
//		noticeRef    NoticeReference OPTIONAL,
//		explicitText DisplayText	 OPTIONAL 
//	}

public final class UserNotice extends Sequence<IEncodable>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(NoticeReference.class).factory(), Cast.O), 
		new ObjectInfo(new ChoiceCreator(DisplayText    .class).factory(), Cast.O), 
	}; 
	// конструктор при раскодировании
	public UserNotice(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public UserNotice(NoticeReference noticeRef, OctetString explicitText) 
	{
		super(info, noticeRef, explicitText); 
	} 
	public final NoticeReference    noticeRef   () { return (NoticeReference)get(0); } 
	public final OctetString        explicitText() { return (OctetString    )get(1); }
}
