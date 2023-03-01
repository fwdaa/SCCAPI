package aladdin.asn1.iso.ocsp;
import aladdin.asn1.*;
import java.io.*;

// OCSPResponse ::= SEQUENCE {
//    responseStatus              OCSPResponseStatus,
//    responseBytes  [0] EXPLICIT ResponseBytes OPTIONAL
// }

public class OCSPResponse extends Sequence<IEncodable>
{
    private static final long serialVersionUID = -4592579215281690593L;

    // информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(Enumerated   .class).factory(), Cast.N                 ), 
		new ObjectInfo(new ObjectCreator(ResponseBytes.class).factory(), Cast.EO, Tag.context(0)) 
	}; 
	// конструктор при раскодировании
	public OCSPResponse(IEncodable encodable) throws IOException { super(encodable, info); }
    
	// конструктор при закодировании
	public OCSPResponse(Enumerated responseStatus, ResponseBytes responseBytes) 
	{ 
		super(info, responseStatus, responseBytes); 
	}
	public final Enumerated    responseStatus() { return (Enumerated   )get(0); } 
	public final ResponseBytes responseBytes () { return (ResponseBytes)get(1); }
}
