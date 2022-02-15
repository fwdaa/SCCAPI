package aladdin.asn1.iso.pkix.ce;
import aladdin.asn1.*; 
import aladdin.asn1.Boolean; 
import aladdin.asn1.Integer; 
import java.io.*; 

//	BasicConstraints ::= SEQUENCE {
//		cA                BOOLEAN DEFAULT FALSE,
//		pathLenConstraint INTEGER (0..MAX) OPTIONAL 
//	}

public final class BasicConstraints extends Sequence<IEncodable>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(Boolean.class).factory( ), Cast.O, Tag.ANY, Boolean.FALSE), 
		new ObjectInfo(new ObjectCreator(Integer.class).factory(0), Cast.O, Tag.ANY				  ), 
	}; 
	// конструктор при раскодировании
	public BasicConstraints(IEncodable encodable) throws IOException { super(encodable, info); }
	
	// конструктор при закодировании
	public BasicConstraints(Boolean cA, Integer pathLenConstraint) 
	{
		super(info, cA, pathLenConstraint); 
	}
	public final Boolean ca				  () { return (Boolean)get(0); } 
	public final Integer pathLenConstraint() { return (Integer)get(1); }
}
