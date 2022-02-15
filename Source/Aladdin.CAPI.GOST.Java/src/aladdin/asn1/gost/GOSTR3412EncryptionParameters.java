package aladdin.asn1.gost;
import aladdin.asn1.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// GostR3412-15-Encryption-Parameters ::= SEQUENCE
// {
//      ukm OCTET STRING
// }
///////////////////////////////////////////////////////////////////////////////
public class GOSTR3412EncryptionParameters extends Sequence<IEncodable>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(OctetString.class).factory(), Cast.N), 
	}; 
	// конструктор при раскодировании
	public GOSTR3412EncryptionParameters(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public GOSTR3412EncryptionParameters(OctetString ukm) { super(info, ukm); }

    public OctetString ukm() { return (OctetString)get(0); } 
}
