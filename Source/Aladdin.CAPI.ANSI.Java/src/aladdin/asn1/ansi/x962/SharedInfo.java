package aladdin.asn1.ansi.x962; 
import aladdin.asn1.*; 
import aladdin.asn1.iso.*; 
import java.io.*; 

////////////////////////////////////////////////////////////////////////////////
// ASN1SharedInfo ::= SEQUENCE {
//      keyInfo AlgorithmIdentifier,
//      entityUInfo  [0] EXPLICIT OCTET STRING OPTIONAL,
//      entityVInfo  [1] EXPLICIT OCTET STRING OPTIONAL,
//      suppPubInfo  [2] EXPLICIT OCTET STRING OPTIONAL,
//      suppPrivInfo [3] EXPLICIT OCTET STRING OPTIONAL
// }
////////////////////////////////////////////////////////////////////////////////
public final class SharedInfo extends Sequence<IEncodable>
{
    private static final long serialVersionUID = 6755859612731961181L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(AlgorithmIdentifier.class).factory(), Cast.EO, Tag.ANY       ), 
		new ObjectInfo(new ObjectCreator(OctetString        .class).factory(), Cast.N , Tag.context(0)), 
		new ObjectInfo(new ObjectCreator(OctetString        .class).factory(), Cast.EO, Tag.context(1)),
		new ObjectInfo(new ObjectCreator(OctetString        .class).factory(), Cast.EO, Tag.context(2)), 
		new ObjectInfo(new ObjectCreator(OctetString        .class).factory(), Cast.EO, Tag.context(3)) 
	}; 
	// конструктор при раскодировании
	public SharedInfo(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public SharedInfo(AlgorithmIdentifier keyInfo, OctetString entityUInfo, 
        OctetString entityVInfo, OctetString suppPubInfo, OctetString suppPrivInfo) 
    { 
        super(info, keyInfo, entityUInfo, entityVInfo, suppPubInfo, suppPrivInfo); 
    }
	public final AlgorithmIdentifier keyInfo     () { return (AlgorithmIdentifier   )get(0); }
	public final OctetString         entityUInfo () { return (OctetString           )get(1); }
	public final OctetString         entityVInfo () { return (OctetString           )get(2); }
	public final OctetString         suppPubInfo () { return (OctetString           )get(3); }
	public final OctetString         suppPrivInfo() { return (OctetString           )get(4); }
}
