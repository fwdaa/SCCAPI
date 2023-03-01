package aladdin.asn1.iso.ocsp;
import aladdin.asn1.*;
import aladdin.asn1.iso.pkix.*;
import java.io.*;

// Request ::= SEQUENCE {
//     reqCert                              CertID,
//     singleRequestExtensions [0] EXPLICIT Extensions { {re-ocsp-service-locator, ...}} OPTIONAL
// }

public class Request extends Sequence<IEncodable>
{
    private static final long serialVersionUID = -3057462981192269098L;

    // информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(CertID    .class).factory(), Cast.N                 ), 
		new ObjectInfo(new ObjectCreator(Extensions.class).factory(), Cast.EO, Tag.context(0)), 
	}; 
	// конструктор при раскодировании
	public Request(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public Request(CertID reqCert, Extensions singleRequestExtensions) 
	{ 
		super(info, reqCert, singleRequestExtensions); 
	}
	public final CertID     reqCert                 () { return (CertID    )get(0); } 
	public final Extensions singleRequestExtensions () { return (Extensions)get(1); }
}
