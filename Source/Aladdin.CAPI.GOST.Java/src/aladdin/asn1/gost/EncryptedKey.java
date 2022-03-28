package aladdin.asn1.gost;
import aladdin.asn1.*; 
import java.io.*; 

//	GOST28147EncryptedKey ::= SEQUENCE {
//		encryptedKey				OCTET STRING (SIZE (32 | 64)),
//		maskKey      [0] IMPLICIT	OCTET STRING (SIZE (32 | 64)) OPTIONAL,
//		macKey						OCTET STRING (SIZE (4))
//	}

public final class EncryptedKey extends Sequence<OctetString>
{
    private static final long serialVersionUID = 7690035948344465889L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(OctetString.class).factory(32, 64), Cast.N,	Tag.ANY			), 
		new ObjectInfo(new ObjectCreator(OctetString.class).factory(32, 64), Cast.O,	Tag.context(0)	), 
		new ObjectInfo(new ObjectCreator(OctetString.class).factory( 4,  4), Cast.N,	Tag.ANY			), 
	}; 
	// конструктор при раскодировании
	public EncryptedKey(IEncodable encodable) throws IOException { super(encodable, info); }
    
	// конструктор при закодировании
	public EncryptedKey(OctetString encryptedKey, OctetString maskKey, OctetString macKey)
	{
		super(info, encryptedKey, maskKey, macKey); 
	}
	public final OctetString encrypted() { return get(0); } 
	public final OctetString maskKey  () { return get(1); }
	public final OctetString macKey	  () { return get(2); }
}
