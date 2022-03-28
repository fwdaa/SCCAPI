package aladdin.asn1.ansi.x942; 
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import java.io.*; 

// ValidationParms ::= SEQUENCE {
//		seed            BIT STRING,
//		pgenCounter     INTEGER 
// }

public final class ValidationParms extends Sequence<IEncodable>
{
    private static final long serialVersionUID = 1037367797286659513L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(BitString.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(Integer  .class).factory(), Cast.N), 
	}; 
	// конструктор при раскодировании
	public ValidationParms(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public ValidationParms(BitString seed, Integer counter)
    {
		super(info, seed, counter); 
    }
	public final BitString  seed	() { return (BitString)get(0); } 
	public final Integer    counter () { return (Integer  )get(1); }
}
