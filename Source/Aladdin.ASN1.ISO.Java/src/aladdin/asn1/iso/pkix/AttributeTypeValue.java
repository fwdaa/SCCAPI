package aladdin.asn1.iso.pkix;
import aladdin.asn1.*; 
import java.io.*;

//	AttributeTypeValue ::= SEQUENCE {
//		type    OBJECT IDENTIFIER,
//		value   ANY DEFINED BY type
//	}
public final class AttributeTypeValue extends Sequence<IEncodable>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(ObjectIdentifier.class).factory(), Cast.N, Tag.ANY), 
		new ObjectInfo(    ImplicitCreator				        .factory  , Cast.N, Tag.ANY), 
	}; 
	// конструктор при раскодировании
	public AttributeTypeValue(IEncodable encodable) throws IOException { super(encodable, info); }
		
	// конструктор при закодировании
	public AttributeTypeValue(ObjectIdentifier type, IEncodable value) 
	{
		super(info, type, value); 
	}
	public final ObjectIdentifier type ()	{ return (ObjectIdentifier)get(0); } 
	public final IEncodable		  value()	{ return			       get(1); }
}
