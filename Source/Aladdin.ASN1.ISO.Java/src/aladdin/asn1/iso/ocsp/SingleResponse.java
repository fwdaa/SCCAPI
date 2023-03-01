package aladdin.asn1.iso.ocsp;
import aladdin.asn1.*;
import aladdin.asn1.iso.pkix.*;
import java.io.*;

// SingleResponse ::= SEQUENCE {
//      certID                        CertID,
//      certStatus                    CertStatus,
//      thisUpdate                    GeneralizedTime,
//      nextUpdate       [0] EXPLICIT GeneralizedTime OPTIONAL,
//      singleExtensions [1] EXPLICIT Extensions {{re-ocsp-crl | re-ocsp-archive-cutoff | CrlEntryExtensions, ...}} OPTIONAL
// }

public class SingleResponse extends Sequence<IEncodable>
{
    private static final long serialVersionUID = -6105037762146195395L;

    // информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(CertID         .class).factory(), Cast.N                 ), 
		new ObjectInfo(new ChoiceCreator(CertStatus     .class).factory(), Cast.N                 ), 
		new ObjectInfo(new ObjectCreator(GeneralizedTime.class).factory(), Cast.N                 ), 
		new ObjectInfo(new ObjectCreator(GeneralizedTime.class).factory(), Cast.EO, Tag.context(0)), 
		new ObjectInfo(new ObjectCreator(Extensions     .class).factory(), Cast.EO, Tag.context(1)) 
	}; 
	// конструктор при раскодировании
	public SingleResponse(IEncodable encodable) throws IOException { super(encodable, info); }
    
	// конструктор при закодировании
	public SingleResponse(CertID certID, IEncodable certStatus, 
        GeneralizedTime thisUpdate, GeneralizedTime nextUpdate, Extensions singleExtensions) 
	{ 
		super(info, certID, certStatus, thisUpdate, nextUpdate, singleExtensions); 
	}
	public final CertID             certID          () { return (CertID         )get(0); } 
	public final IEncodable         certStatus      () { return                  get(1); }
	public final GeneralizedTime    thisUpdate      () { return (GeneralizedTime)get(2); }
	public final GeneralizedTime    nextUpdate      () { return (GeneralizedTime)get(3); }
	public final Extensions         singleExtensions() { return (Extensions     )get(4); }
}
