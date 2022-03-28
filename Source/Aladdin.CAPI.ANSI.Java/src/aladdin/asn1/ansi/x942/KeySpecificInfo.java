package aladdin.asn1.ansi.x942; 
import aladdin.asn1.*; 
import java.io.*; 

// KeySpecificInfo ::= SEQUENCE {
//		algorithm	OBJECT IDENTIFIER,
//		counter		OCTET STRING SIZE (4..4) 
//	}

public final class KeySpecificInfo extends Sequence<IEncodable>
{
    private static final long serialVersionUID = 7000764026175169296L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(ObjectIdentifier .class).factory(    ), Cast.N), 
		new ObjectInfo(new ObjectCreator(OctetString      .class).factory(4, 4), Cast.N), 
	}; 
	// конструктор при раскодировании
	public KeySpecificInfo(IEncodable encodable) throws IOException { super(encodable, info); }
    
	// конструктор при закодировании
	public KeySpecificInfo(ObjectIdentifier algorithm, OctetString counter)
	{
        // вызвать базовую функцию
		super(info, algorithm, counter); 
	}
	public final ObjectIdentifier algorithm() { return (ObjectIdentifier)get(0); } 
	public final OctetString	  counter  () { return (OctetString     )get(1); }
}
