package aladdin.asn1.ansi; 
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import java.io.*; 

//	FBParameter ::= SEQUENCE {
//		iv				OCTET STRING,
//		numberOfBits	INTEGER
//	}

public final class FBParameter extends Sequence<IEncodable>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

        new ObjectInfo(new ObjectCreator(OctetString  .class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(Integer      .class).factory(), Cast.N), 
	}; 
	// конструктор при раскодировании
	public FBParameter(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public FBParameter(OctetString iv, Integer numberOfBits) 
    {
        super(info, iv, numberOfBits); 
    }
	public final OctetString	iv			()	{ return (OctetString	)get(0); }
	public final Integer		numberOfBits()	{ return (Integer		)get(1); }
}
