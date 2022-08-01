package aladdin.asn1.iso.pkix.ce;
import aladdin.asn1.*;
import aladdin.asn1.iso.pkix.*;
import java.io.*;

// AccessDescription  ::=  SEQUENCE {
//		accessMethod   OBJECT IDENTIFIER,
//      accessLocation GeneralName  
// }

public final class AccessDescription extends Sequence<IEncodable>
{
    // private static final long serialVersionUID = -2430558462928212991L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(ObjectIdentifier.class).factory(), Cast.N), 
		new ObjectInfo(new ChoiceCreator(GeneralName	 .class).factory(), Cast.N) 
	}; 
	// конструктор при раскодировании
	public AccessDescription(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public AccessDescription(ObjectIdentifier accessMethod, IEncodable accessLocation) 
	{
		super(info, accessMethod, accessLocation); 
	}
	public final ObjectIdentifier accessMethod  () { return (ObjectIdentifier   )get(0); } 
	public final IEncodable       accessLocation() { return (IEncodable         )get(1); }
}
