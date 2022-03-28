package aladdin.asn1.kz;
import aladdin.asn1.*;
import aladdin.asn1.Integer;
import java.io.*; 

//	EncryptedKey ::= SEQUENCE {
//      version            INTEGER, 
//		iv                 OCTET STRING (SIZE (8)),
//      spc                OCTET STRING, 
//		encrypted          OCTET STRING OPTIONAL, 
//		ukm                [0] IMPLICIT OCTET STRING (SIZE (8)) OPTIONAL
//	}

public class EncryptedKey extends Sequence<IEncodable>
{
    private static final long serialVersionUID = -3041902074030430561L;
    
    // информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(Integer	.class).factory(    ), Cast.N, Tag.ANY       ), 
		new ObjectInfo(new ObjectCreator(OctetString.class).factory(8, 8), Cast.N, Tag.ANY       ), 
		new ObjectInfo(new ObjectCreator(OctetString.class).factory(    ), Cast.N, Tag.ANY       ), 
		new ObjectInfo(new ObjectCreator(OctetString.class).factory(    ), Cast.O, Tag.ANY       ), 
		new ObjectInfo(new ObjectCreator(OctetString.class).factory(8, 8), Cast.O, Tag.context(0)) 
	}; 
	// конструктор при раскодировании
	public EncryptedKey(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public EncryptedKey(Integer version, OctetString iv, 
        OctetString spc, OctetString encrypted, OctetString ukm) 
    {
        super(info, version, iv, spc, encrypted, ukm); 
    }  
	public final Integer		version   () { return (Integer		)get(0); } 
	public final OctetString	iv	      () { return (OctetString	)get(1); } 
	public final OctetString	spc       () { return (OctetString	)get(2); } 
	public final OctetString	encrypted () { return (OctetString	)get(3); } 
	public final OctetString	ukm       () { return (OctetString	)get(4); } 
}
