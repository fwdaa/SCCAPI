package aladdin.asn1.iso;
import aladdin.asn1.*; 
import java.io.*;

//	Attribute ::= SEQUENCE {
//		type	OBJECT IDENTIFIER,
//		values	SET OF ANY DEFINED BY type
//	}

public final class Attribute extends Sequence<IEncodable>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(ObjectIdentifier.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(Set             .class).factory(), Cast.N), 
	}; 
	// конструктор при раскодировании
	public Attribute(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public Attribute(ObjectIdentifier type, Set<? extends IEncodable> values) 
	{ 
		super(info, type, values);
	}
	public final ObjectIdentifier           type  () { return (ObjectIdentifier         )get(0); } 
	public final Set<? extends IEncodable>	values() { return (Set<? extends IEncodable>)get(1); }
}
