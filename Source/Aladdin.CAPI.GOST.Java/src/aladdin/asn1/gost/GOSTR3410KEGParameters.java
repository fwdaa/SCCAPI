package aladdin.asn1.gost;
import aladdin.asn1.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// GostR3410-12-KEG-Parameters ::= SEQUENCE
// {
//      algorithm OBJECT IDENTIFIER
// }
///////////////////////////////////////////////////////////////////////////////
public final class GOSTR3410KEGParameters extends Sequence<IEncodable>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(ObjectIdentifier.class).factory(), Cast.N), 
	}; 
	// конструктор при раскодировании
	public GOSTR3410KEGParameters(IEncodable encodable) throws IOException { super(encodable, info); }
    
	// конструктор при закодировании
	public GOSTR3410KEGParameters(ObjectIdentifier algorithm) { super(info, algorithm); }
    
	public final ObjectIdentifier algorithm() { return (ObjectIdentifier)get(0); } 
}
