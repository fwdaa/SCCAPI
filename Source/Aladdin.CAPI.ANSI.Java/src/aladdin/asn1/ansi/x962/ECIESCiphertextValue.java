package aladdin.asn1.ansi.x962; 
import aladdin.asn1.*; 
import java.io.*; 

////////////////////////////////////////////////////////////////////////////////
// ECIES-Ciphertext-Value ::= SEQUENCE {
//      ephemeralPublicKey ECPoint,
//      symmetricCiphertext OCTET STRING,
//      macTag OCTET STRING
// }
////////////////////////////////////////////////////////////////////////////////
public final class ECIESCiphertextValue extends Sequence<OctetString>
{
    private static final long serialVersionUID = 3283983043795388216L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(OctetString.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(OctetString.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(OctetString.class).factory(), Cast.N), 
	}; 
	// конструктор при раскодировании
	public ECIESCiphertextValue(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public ECIESCiphertextValue(OctetString ephemeralPublicKey, 
        OctetString symmetricCiphertext, OctetString macTag) 
    { 
        super(info, ephemeralPublicKey, symmetricCiphertext, macTag); 
    }
	public final OctetString ephemeralPublicKey () { return get(0); }
	public final OctetString symmetricCiphertext() { return get(1); }
	public final OctetString macTag             () { return get(2); }
}
