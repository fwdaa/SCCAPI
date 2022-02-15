package aladdin.asn1.ansi.x962;
import aladdin.asn1.*;
import aladdin.asn1.Integer;
import java.io.*;

////////////////////////////////////////////////////////////////////////////////
// ECDSA-Full-R ::= SEQUENCE {
//      r ECPoint,
//      s INTEGER
// }
////////////////////////////////////////////////////////////////////////////////
public class ECDSAFullR extends Sequence<IEncodable>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 
        
		new ObjectInfo(new ObjectCreator(OctetString.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(Integer    .class).factory(), Cast.N), 
	}; 
	// конструктор при раскодировании
	public ECDSAFullR(IEncodable encodable) throws IOException { super(encodable, info); }
    
	// конструктор при закодировании
	public ECDSAFullR(OctetString r, Integer s) { super(info, r, s); }
    
	public final OctetString r() { return (OctetString)get(0); } 
	public final Integer     s() { return (Integer    )get(1); } 
}
