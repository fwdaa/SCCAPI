package aladdin.asn1.stb;
import aladdin.asn1.*; 
import java.io.*; 

////////////////////////////////////////////////////////////////////////////////
// Curve ::= SEQUENCE {
//  a OCTET STRING (SIZE(32|48|64)),
//  b OCTET STRING (SIZE(32|48|64)),
//  seed BIT STRING (SIZE(64))
// }
////////////////////////////////////////////////////////////////////////////////
public final class Curve extends Sequence<IEncodable>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 
        
		new ObjectInfo(new ObjectCreator(OctetString.class).factory(32, 64), Cast.N), 
		new ObjectInfo(new ObjectCreator(OctetString.class).factory(32, 64), Cast.N), 
		new ObjectInfo(new ObjectCreator(BitString  .class).factory(64, 64), Cast.N), 
	}; 
	// конструктор при раскодировании
	public Curve(IEncodable encodable) throws IOException { super(encodable, info); 
    
        // определить размеры параметров
        int lengthA = a().value().length; int lengthB = b().value().length;
    
        // проверить корректность параметров
        if (lengthA != 32 && lengthA != 48 && lengthA != 64) throw new IOException(); 
        if (lengthB != 32 && lengthB != 48 && lengthB != 64) throw new IOException(); 
    }  
    
	// конструктор при закодировании
	public Curve(OctetString a, OctetString b, BitString seed) { super(info, a, b, seed); 
    
        // определить размеры параметров
        int lengthA = a.value().length; int lengthB = b.value().length;
    
        // проверить корректность параметров
        if (lengthA != 32 && lengthA != 48 && lengthA != 64) throw new IllegalArgumentException(); 
        if (lengthB != 32 && lengthB != 48 && lengthB != 64) throw new IllegalArgumentException(); 
	}
	public final OctetString a   () { return (OctetString)get(0); } 
	public final OctetString b   () { return (OctetString)get(1); } 
	public final BitString   seed() { return (BitString  )get(2); } 
}
