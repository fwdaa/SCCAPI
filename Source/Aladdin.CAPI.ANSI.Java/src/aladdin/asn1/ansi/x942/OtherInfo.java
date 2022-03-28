package aladdin.asn1.ansi.x942; 
import aladdin.asn1.*; 
import java.io.*; 

// OtherInfo ::= SEQUENCE {
//	keyInfo		KeySpecificInfo,
//	partyAInfo	[0] EXPLICIT OCTET STRING OPTIONAL,
//	suppPubInfo [2] EXPLICIT OCTET STRING
// }

public final class OtherInfo extends Sequence<IEncodable>
{
    private static final long serialVersionUID = -4521340698603393336L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(KeySpecificInfo.class).factory(), Cast.N , Tag.ANY       ), 
		new ObjectInfo(new ObjectCreator(OctetString    .class).factory(), Cast.EO, Tag.context(0)), 
		new ObjectInfo(new ObjectCreator(OctetString    .class).factory(), Cast.E , Tag.context(2)), 
	}; 
	// конструктор при раскодировании
	public OtherInfo(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public OtherInfo(KeySpecificInfo keyInfo, OctetString partyAInfo, 
		OctetString suppPubInfo) 
    {
        super(info, keyInfo, partyAInfo, suppPubInfo); 
    }  
    public final KeySpecificInfo    keyInfo	   () { return (KeySpecificInfo )get(0); } 
	public final OctetString        partyAInfo () { return (OctetString     )get(1); }
	public final OctetString        suppPubInfo() { return (OctetString     )get(2); }
}
