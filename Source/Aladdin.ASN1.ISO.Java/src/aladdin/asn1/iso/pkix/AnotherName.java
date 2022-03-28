package aladdin.asn1.iso.pkix;
import aladdin.asn1.*; 
import java.io.*;

//	AnotherName ::= SEQUENCE {
//		type-id    OBJECT IDENTIFIER,
//		value      [0] EXPLICIT ANY DEFINED BY type-id 
//	}

public final class AnotherName extends Sequence<IEncodable>
{
    private static final long serialVersionUID = -2004599008123093969L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(ObjectIdentifier.class).factory(), Cast.N, Tag.ANY		  ), 
		new ObjectInfo(    ImplicitCreator				        .factory  , Cast.E, Tag.context(0)), 
	}; 
	// конструктор при раскодировании
	public AnotherName(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public AnotherName(ObjectIdentifier typeId, IEncodable value) 
	{
		super(info, typeId, value); 
	}
	public final ObjectIdentifier   typeId() { return (ObjectIdentifier)get(0); } 
	public final IEncodable         value () { return                   get(1); }
}
