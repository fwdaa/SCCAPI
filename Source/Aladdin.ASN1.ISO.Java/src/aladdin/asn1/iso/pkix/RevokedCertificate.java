package aladdin.asn1.iso.pkix;
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import java.io.*; 

//	RevokedCertificate ::= SEQUENCE  {
//		userCertificate    INTEGER,
//		revocationDate     Time,
//		crlEntryExtensions Extensions OPTIONAL
//	} 

public final class RevokedCertificate extends Sequence<IEncodable>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(Integer    .class).factory(), Cast.N), 
		new ObjectInfo(new ChoiceCreator(Time		.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(Extensions	.class).factory(), Cast.O), 
	}; 
	// конструктор при раскодировании
	public RevokedCertificate(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public RevokedCertificate(Integer userCertificate, 
		VisibleString revocationDate, Extensions crlEntryExtensions) 
	{ 
		super(info, userCertificate, revocationDate, crlEntryExtensions); 
	}
	public final Integer        userCertificate	  () { return (Integer      )get(0); } 
	public final VisibleString	revocationDate	  () { return (VisibleString)get(1); }
	public final Extensions		crlEntryExtensions() { return (Extensions	)get(2); }
}
