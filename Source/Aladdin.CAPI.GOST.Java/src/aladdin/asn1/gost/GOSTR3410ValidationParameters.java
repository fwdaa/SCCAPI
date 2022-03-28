package aladdin.asn1.gost;
import aladdin.asn1.*;
import aladdin.asn1.Integer;
import java.io.*;

// GostR3410-94-ValidationParameters-c ::= INTEGER (0 .. 65535)
// GostR3410-94-ValidationParameters ::= SEQUENCE {
//      x0   GostR3410-94-ValidationParameters-c,
//      c    GostR3410-94-ValidationParameters-c,
//      d    INTEGER OPTIONAL -- 1 < d < p-1 < 2^1024-1
// }
// GostR3410-94-ValidationBisParameters-c ::= INTEGER (0 .. 4294967295)
// GostR3410-94-ValidationBisParameters ::=  SEQUENCE {
//      x0   GostR3410-94-ValidationBisParameters-c,
//      c    GostR3410-94-ValidationBisParameters-c,
//      d    INTEGER OPTIONAL -- 1 < d < p-1 < 2^1024-1
// }

public final class GOSTR3410ValidationParameters extends Sequence<Integer>
{
    private static final long serialVersionUID = -1679931220090928879L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

        new ObjectInfo(new ObjectCreator(Integer.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(Integer.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(Integer.class).factory(), Cast.O) 
	}; 
	// конструктор при раскодировании
	public GOSTR3410ValidationParameters(IEncodable encodable) throws IOException { super(encodable, info); }
		
	// конструктор при закодировании
	public GOSTR3410ValidationParameters(Integer x0, Integer c, Integer d) 
    {
        super(info, x0, c, d); 
    }  
	public final Integer x0() { return get(0); } 
	public final Integer c () { return get(1); } 
	public final Integer d () { return get(2); } 
}
