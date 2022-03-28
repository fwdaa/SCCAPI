package aladdin.asn1.stb;
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import java.io.*; 

////////////////////////////////////////////////////////////////////////////////
// BDHKeytransParams ::= SEQUENCE {
// 		va INTEGER,
// 		mac OCTET STRING (SIZE(4)),
// 		sblock OBJECT IDENTIFIER OPTIONAL
// 	}
////////////////////////////////////////////////////////////////////////////////
public final class BDHKeyTransParams extends Sequence<IEncodable>
{
    private static final long serialVersionUID = 5488286253194901179L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

        new ObjectInfo(new ObjectCreator(Integer            .class).factory(    ), Cast.N), 
        new ObjectInfo(new ObjectCreator(OctetString 		.class).factory(4, 4), Cast.N), 
		new ObjectInfo(new ObjectCreator(ObjectIdentifier   .class).factory(    ), Cast.O) 
	}; 
	// конструктор при раскодировании
	public BDHKeyTransParams(IEncodable encodable) throws IOException { super(encodable, info); } 
    
	// конструктор при закодировании
	public BDHKeyTransParams(Integer va, OctetString mac, ObjectIdentifier sblock) 
	{
		super(info, va, mac, sblock); 
	}  
	public final Integer            va    () { return (Integer	       )get(0); } 
	public final OctetString		mac   () { return (OctetString	   )get(1); } 
	public final ObjectIdentifier	sblock() { return (ObjectIdentifier)get(2); }
}
