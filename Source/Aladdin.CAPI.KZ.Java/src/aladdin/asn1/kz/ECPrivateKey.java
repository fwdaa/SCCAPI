package aladdin.asn1.kz;
import aladdin.asn1.*;
import aladdin.asn1.Integer;
import java.io.*; 

//	ECPrivateKey ::= SEQUENCE {
//      version            INTEGER (1), 
//		value              OCTET STRING (SIZE (32))
//	}

public class ECPrivateKey extends Sequence<IEncodable>
{
    private static final long serialVersionUID = 395443026244672906L;
    
    // информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(Integer	.class).factory(      ), Cast.N, Tag.ANY), 
		new ObjectInfo(new ObjectCreator(OctetString.class).factory(32, 32), Cast.N, Tag.ANY) 
	}; 
	// конструктор при раскодировании
	public ECPrivateKey(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public ECPrivateKey(Integer version, OctetString value) 
    {
        super(info, version, value); 
    }  
	public final Integer		version() { return (Integer		)get(0); } 
	public final OctetString	value  () { return (OctetString	)get(1); } 
}
