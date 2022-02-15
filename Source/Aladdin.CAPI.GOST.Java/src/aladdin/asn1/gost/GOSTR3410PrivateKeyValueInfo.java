package aladdin.asn1.gost;
import aladdin.asn1.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// GostR3410-2001-KeyValueMask ::= OCTET STRING;
// GostR3410-2001-PublicKey    ::= OCTET STRING {PubKeyX | PubKeyY};
// GostR3410-2001-KeyValueInfo ::= SEQUENCE{
// 	GostR3410-2001-KeyValueMask,
// 	GostR3410-2001-PublicKey 
// }
///////////////////////////////////////////////////////////////////////////////
public final class GOSTR3410PrivateKeyValueInfo extends Sequence<OctetString>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(OctetString.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(OctetString.class).factory(), Cast.N), 
	}; 
	// конструктор при раскодировании
	public GOSTR3410PrivateKeyValueInfo(IEncodable encodable) throws IOException { super(encodable, info); }

    // конструктор при закодировании
	public GOSTR3410PrivateKeyValueInfo(OctetString privateKeyMaskValue, 
		OctetString publicKeyValue)
    {
        super(info, privateKeyMaskValue, publicKeyValue); 
    }
    public final OctetString privateKeyMaskValue() { return get(0); } 
	public final OctetString publicKeyValue     () { return get(1); }
}
