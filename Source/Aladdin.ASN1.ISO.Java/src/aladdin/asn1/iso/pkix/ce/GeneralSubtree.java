package aladdin.asn1.iso.pkix.ce;
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import aladdin.asn1.iso.pkix.*; 
import java.io.*; 

//	GeneralSubtree ::= SEQUENCE {
//		base                 GeneralName,
//		minimum [0] IMPLICIT INTEGER (0..MAX) DEFAULT 0,
//		maximum [1] IMPLICIT INTEGER (0..MAX) OPTIONAL 
//	}

public final class GeneralSubtree extends Sequence<IEncodable>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ChoiceCreator(GeneralName.class).factory( ), Cast.N, Tag.ANY                         ), 
		new ObjectInfo(new ObjectCreator(Integer	.class).factory(0), Cast.O, Tag.context(0), new Integer(0)	), 
		new ObjectInfo(new ObjectCreator(Integer	.class).factory(0), Cast.O, Tag.context(1)                  ), 
	}; 
	// конструктор при раскодировании
	public GeneralSubtree(IEncodable encodable) throws IOException { super(encodable, info); }
	
	// конструктор при закодировании
	public GeneralSubtree(IEncodable base, Integer minimum, 
		Integer maximum) 
	{
		super(info, base, minimum, maximum); 
	}
	public final IEncodable	base	() { return          get(0); } 
	public final Integer    minimum	() { return (Integer)get(1); }
	public final Integer    maximum	() { return (Integer)get(2); }
}
