package aladdin.asn1.iso.pkcs.pkcs5;
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import java.io.*; 

//	PBEParameter ::= SEQUENCE {
//		salt			OCTET STRING,
//		iterationCount	INTEGER
//	}

public final class PBEParameter extends Sequence<IEncodable>
{
    private static final long serialVersionUID = 8966230569395551373L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(OctetString.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(Integer    .class).factory(), Cast.N), 
	}; 
	// конструктор при раскодировании
	public PBEParameter(IEncodable encodable) throws IOException { super(encodable, info); } 
	
	// конструктор при закодировании
	public PBEParameter(OctetString salt, Integer iterationCount) 
	{
		super(info, salt, iterationCount); 
	}
	public final OctetString	salt			() { return (OctetString)get(0); }
	public final Integer        iterationCount	() { return (Integer	)get(1); }
}
