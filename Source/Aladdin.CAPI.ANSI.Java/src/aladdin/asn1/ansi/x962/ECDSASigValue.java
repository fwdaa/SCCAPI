package aladdin.asn1.ansi.x962; 
import aladdin.asn1.*; 
import aladdin.asn1.Boolean; 
import aladdin.asn1.Integer; 
import java.io.*; 

////////////////////////////////////////////////////////////////////////////////
// ECDSASigValue ::= SEQUENCE {
//		r            INTEGER,
//		s            INTEGER, 
//		a            INTEGER OPTIONAL, 
//		y CHOICE { b BOOLEAN, f FieldElement } OPTIONAL 
// }
////////////////////////////////////////////////////////////////////////////////
public final class ECDSASigValue extends Sequence<IEncodable>
{
    public static final class Y extends Choice
    {
        // информация о структуре
        private static final ObjectInfo[] info = new ObjectInfo[] { 

            new ObjectInfo(new ObjectCreator(Boolean    .class).factory(), Cast.N), 
            new ObjectInfo(new ObjectCreator(OctetString.class).factory(), Cast.N) 
        }; 
        // конструктор
        public Y() { super(info); } 
    }
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(Integer.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(Integer.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(Integer.class).factory(), Cast.O), 
		new ObjectInfo(new ChoiceCreator(Y      .class).factory(), Cast.O) 
	}; 
	// конструктор при раскодировании
	public ECDSASigValue(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public ECDSASigValue(Integer r, Integer s, Integer a, IEncodable y) { super(info, r, s, a, y); }

	public final Integer    r() { return (Integer)get(0); }
	public final Integer    s() { return (Integer)get(1); }
	public final Integer    a() { return (Integer)get(2); }
	public final IEncodable y() { return          get(3); }
}
