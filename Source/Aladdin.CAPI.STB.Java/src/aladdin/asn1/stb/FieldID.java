package aladdin.asn1.stb;
import aladdin.asn1.*;
import aladdin.asn1.Integer;
import java.io.*;

////////////////////////////////////////////////////////////////////////////////
// FieldID ::= SEQUENCE {
//  fieldType OBJECT IDENTIFIER (bign-primefield),
//  parameters INTEGER
// }
////////////////////////////////////////////////////////////////////////////////
public final class FieldID extends Sequence<IEncodable>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 
        
		new ObjectInfo(new ObjectCreator(ObjectIdentifier   .class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(Integer            .class).factory(), Cast.N), 
	}; 
	// конструктор при раскодировании
	public FieldID(IEncodable encodable) throws IOException { super(encodable, info); }  
    
	// конструктор при закодировании
	public FieldID(ObjectIdentifier fieldType, Integer parameters)
	{
		super(info, fieldType, parameters); 
	}
	public final ObjectIdentifier   fieldType () { return (ObjectIdentifier )get(0); } 
	public final Integer            parameters() { return (Integer          )get(1); } 
}
