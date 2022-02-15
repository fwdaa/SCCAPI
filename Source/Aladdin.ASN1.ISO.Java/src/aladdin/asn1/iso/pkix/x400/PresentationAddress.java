package aladdin.asn1.iso.pkix.x400;
import aladdin.asn1.*; 
import java.io.*; 

//	PresentationAddress ::= SEQUENCE {
//		pSelector     [0] EXPLICIT OCTET STRING OPTIONAL,
//		sSelector     [1] EXPLICIT OCTET STRING OPTIONAL,
//		tSelector     [2] EXPLICIT OCTET STRING OPTIONAL,
//		nAddresses    [3] EXPLICIT Addresses 
// }

public final class PresentationAddress extends Sequence<IEncodable>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(OctetString.class).factory(), Cast.EO, Tag.context(0)), 
		new ObjectInfo(new ObjectCreator(OctetString.class).factory(), Cast.EO, Tag.context(1)), 
		new ObjectInfo(new ObjectCreator(OctetString.class).factory(), Cast.EO, Tag.context(2)), 
		new ObjectInfo(new ObjectCreator(Addresses  .class).factory(), Cast.E,  Tag.context(3)), 
	}; 
	// конструктор при раскодировании
	public PresentationAddress(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public PresentationAddress(OctetString pSelector, OctetString sSelector,
		OctetString tSelector, Addresses nAddresses) 
	{
		super(info, pSelector, sSelector, tSelector, nAddresses); 
	}
	public final OctetString	pSelector () { return (OctetString )get(0); }
	public final OctetString	sSelector () { return (OctetString )get(1); }
	public final OctetString	tSelector () { return (OctetString )get(2); }
	public final Addresses      nAddresses() { return (Addresses   )get(3); }
}
