package aladdin.asn1.iso.ocsp;
import aladdin.asn1.*;
import java.io.*;

// RevokedInfo ::= SEQUENCE {
//    revocationTime                GeneralizedTime,
//    revocationReason [0] EXPLICIT CRLReason OPTIONAL
// }

public class RevokedInfo extends Sequence<IEncodable>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(GeneralizedTime.class).factory(), Cast.N                 ), 
		new ObjectInfo(new ObjectCreator(Enumerated     .class).factory(), Cast.EO, Tag.context(0)), 
	}; 
	// конструктор при раскодировании
	public RevokedInfo(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public RevokedInfo(GeneralizedTime revocationTime, Enumerated revocationReason) 
	{ 
		super(info, revocationTime, revocationReason); 
	}
	public final GeneralizedTime revocationTime  () { return (GeneralizedTime)get(0); } 
	public final Enumerated      revocationReason() { return (Enumerated     )get(1); }
}
