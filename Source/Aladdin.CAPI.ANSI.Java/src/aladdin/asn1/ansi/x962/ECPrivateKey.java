package aladdin.asn1.ansi.x962; 
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import java.io.*; 

////////////////////////////////////////////////////////////////////////////////
// ECPrivateKey ::= SEQUENCE {
//      version INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
//      privateKey OCTET STRING,
//      parameters [0] EXPLICIT ECDomainParameters {{ SECGCurveNames }} OPTIONAL,
//      publicKey  [1] EXPLICIT BIT STRING OPTIONAL
// }
////////////////////////////////////////////////////////////////////////////////
public final class ECPrivateKey extends Sequence<IEncodable>
{
    private static final long serialVersionUID = -7222371282383850243L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(Integer            .class).factory(), Cast.N,  Tag.ANY       ), 
		new ObjectInfo(new ObjectCreator(OctetString        .class).factory(), Cast.N,  Tag.ANY       ), 
		new ObjectInfo(new ChoiceCreator(ECDomainParameters .class).factory(), Cast.EO, Tag.context(0)),
		new ObjectInfo(new ObjectCreator(BitString          .class).factory(), Cast.EO, Tag.context(1)) 
	}; 
	// конструктор при раскодировании
	public ECPrivateKey(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public ECPrivateKey(Integer version, OctetString privateKey, 
        IEncodable parameters, BitString publicKey) 
    { 
        super(info, version, privateKey, parameters, publicKey); 
    }
	public final Integer     version   () { return (Integer    )get(0); }
	public final OctetString privateKey() { return (OctetString)get(1); }
	public final IEncodable  parameters() { return              get(2); }
	public final BitString   publicKey () { return (BitString  )get(3); }
}
