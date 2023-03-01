package aladdin.asn1.iso.ocsp;
import aladdin.asn1.*; 
import java.io.*; 

// AcceptableResponses ::= SEQUENCE OF RESPONSE.&id({ResponseSet})

public final class AcceptableResponses extends Sequence<ObjectIdentifier>
{
    private static final long serialVersionUID = 6251036942200275071L;

    // конструктор при раскодировании
	public AcceptableResponses(IEncodable encodable) throws IOException 
	{
		super(encodable);
	}
	// конструктор при закодировании
	public AcceptableResponses(ObjectIdentifier... values) 
	{
		super(ObjectIdentifier.class, values); 
	}
}
