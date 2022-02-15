package aladdin.asn1.ansi; 
import aladdin.asn1.*; 
import java.io.*; 

// Skipjack-Parm ::= SEQUENCE { initialization-vector   OCTET STRING }

public final class SkipjackParm extends Sequence<IEncodable>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

        new ObjectInfo(new ObjectCreator(OctetString  .class).factory(), Cast.N), 
	}; 
	// конструктор при раскодировании
	public SkipjackParm(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public SkipjackParm(OctetString iv) { super(info, iv); }
    
	public final OctetString iv() { return (OctetString)get(0); }
}
