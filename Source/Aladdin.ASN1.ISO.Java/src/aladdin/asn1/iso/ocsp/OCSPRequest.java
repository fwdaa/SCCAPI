package aladdin.asn1.iso.ocsp;
import aladdin.asn1.*;
import java.io.*;

// OCSPRequest ::= SEQUENCE {
//     tbsRequest        TBSRequest,
//     optionalSignature [0] EXPLICIT Signature OPTIONAL
// }

public class OCSPRequest extends Sequence<IEncodable>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(TBSRequest.class).factory(), Cast.N                 ), 
		new ObjectInfo(new ObjectCreator(Signature .class).factory(), Cast.EO, Tag.context(0)) 
	}; 
	// конструктор при раскодировании
	public OCSPRequest(IEncodable encodable) throws IOException { super(encodable, info); }
    
	// конструктор при закодировании
	public OCSPRequest(TBSRequest tbsRequest, Signature optionalSignature) 
	{ 
		super(info, tbsRequest, optionalSignature); 
	}
	public final TBSRequest tbsRequest       () { return (TBSRequest)get(0); } 
	public final Signature  optionalSignature() { return (Signature )get(1); }
}
