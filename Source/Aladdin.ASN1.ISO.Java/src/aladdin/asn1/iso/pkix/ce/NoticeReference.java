package aladdin.asn1.iso.pkix.ce;
import aladdin.asn1.*; 
import java.io.*; 

//	NoticeReference ::= SEQUENCE {
//		organization  DisplayText,
//		noticeNumbers NoticeNumbers
//	}

public final class NoticeReference extends Sequence<IEncodable>
{
    private static final long serialVersionUID = 811553904274701284L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ChoiceCreator(DisplayText  .class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(NoticeNumbers.class).factory(), Cast.N), 
	}; 
	// конструктор при раскодировании
	public NoticeReference(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public NoticeReference(OctetString organization, NoticeNumbers noticeNumbers) 
	{
		super(info, organization, noticeNumbers); 
	}
	public final OctetString    organization () { return (OctetString  )get(0); } 
	public final NoticeNumbers  noticeNumbers() { return (NoticeNumbers)get(1); }
}
