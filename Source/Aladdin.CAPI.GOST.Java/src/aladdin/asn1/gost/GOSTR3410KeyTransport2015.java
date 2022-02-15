package aladdin.asn1.gost;
import aladdin.asn1.*; 
import aladdin.asn1.iso.pkix.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// GostR3410-KeyTransport ::= {
// 	encryptedKey			OCTET STRING,
// 	ephemeralPublicKey		SubjectPublicKeylnfo,
// 	ukm						OCTET STRING
// }
///////////////////////////////////////////////////////////////////////////////
public class GOSTR3410KeyTransport2015 extends Sequence<IEncodable> 
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(OctetString		 .class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(SubjectPublicKeyInfo.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(OctetString         .class).factory(), Cast.N)
	}; 
	// конструктор при раскодировании
	public GOSTR3410KeyTransport2015(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public GOSTR3410KeyTransport2015(OctetString encryptedKey, 
		SubjectPublicKeyInfo ephemeralPublicKey, OctetString ukm) 
    {
        super(info, encryptedKey, ephemeralPublicKey, ukm);   
    }
	public OctetString			encryptedKey	  () { return (OctetString     		)get(0); }
	public SubjectPublicKeyInfo	ephemeralPublicKey() { return (SubjectPublicKeyInfo	)get(1); } 
	public OctetString			ukm				  () { return (OctetString			)get(2); } 
}
