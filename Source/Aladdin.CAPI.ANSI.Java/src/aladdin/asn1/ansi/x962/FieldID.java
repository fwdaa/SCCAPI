package aladdin.asn1.ansi.x962;
import aladdin.asn1.*; 
import java.io.*;

////////////////////////////////////////////////////////////////////////////////
//	FieldID  ::=  SEQUENCE  {
//		fieldType  OBJECT IDENTIFIER,
//		parameters ANY DEFINED BY fieldType  
//	}
////////////////////////////////////////////////////////////////////////////////
public final class FieldID extends Sequence<IEncodable>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(ObjectIdentifier.class).factory(), Cast.N), 
		new ObjectInfo(    ImplicitCreator				        .factory  , Cast.N), 
	};
	// конструктор при раскодировании
	public FieldID(IEncodable encodable) throws IOException { super(encodable, info); }
    
	// конструктор при закодировании
	public FieldID(ObjectIdentifier fieldType, IEncodable parameters) 
	{
		super(info, fieldType, parameters); 
	}
	public final ObjectIdentifier fieldType () { return (ObjectIdentifier)get(0); } 
	public final IEncodable		  parameters() { return                   get(1); }
}
