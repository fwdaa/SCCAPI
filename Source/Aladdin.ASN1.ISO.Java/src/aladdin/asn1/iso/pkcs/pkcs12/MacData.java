package aladdin.asn1.iso.pkcs.pkcs12;
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import aladdin.asn1.iso.pkcs.*; 
import java.io.*; 

//	MacData ::= SEQUENCE {
//		mac			DigestInfo,
//		macSalt		OCTET STRING,
//		iterations	INTEGER			DEFAULT 1
//	}

public final class MacData extends Sequence<IEncodable>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(DigestInfo	.class).factory(), Cast.N,	Tag.ANY                     ), 
		new ObjectInfo(new ObjectCreator(OctetString.class).factory(), Cast.N,	Tag.ANY                     ), 
		new ObjectInfo(new ObjectCreator(Integer    .class).factory(), Cast.O,	Tag.ANY,  new Integer(1)), 
	}; 
	// конструктор при раскодировании
	public MacData(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public MacData(DigestInfo mac, OctetString macSalt, Integer iterations) 
	{
		super(info, mac, macSalt, iterations); 
	}
	public final DigestInfo     mac			() { return (DigestInfo	)get(0); } 
	public final OctetString	macSalt		() { return (OctetString)get(1); }
	public final Integer        iterations	() { return (Integer	)get(2); }
}
