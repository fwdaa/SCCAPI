package aladdin.asn1.iso.pkcs.pkcs7;
import aladdin.asn1.*; 
import java.io.*; 

//	KEKIdentifier ::= SEQUENCE {
//		keyIdentifier	OCTET STRING,
//		date			GeneralizedTime		OPTIONAL,
//		other			OtherKeyAttribute	OPTIONAL 
//	}

public final class KEKIdentifier extends Sequence<IEncodable>
{
    private static final long serialVersionUID = -2903773083738085898L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(OctetString		.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(GeneralizedTime	.class).factory(), Cast.O), 
		new ObjectInfo(new ObjectCreator(OtherKeyAttribute  .class).factory(), Cast.O), 
	}; 
	// конструктор при раскодировании
	public KEKIdentifier(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public KEKIdentifier(OctetString keyIdentifier, GeneralizedTime date, 
		OtherKeyAttribute other) 
	{
		super(info, keyIdentifier, date, other); 
	}
	public final OctetString		keyIdentifier()	{ return (OctetString		)get(0); } 
	public final GeneralizedTime	date		 ()	{ return (GeneralizedTime	)get(1); }
	public final OtherKeyAttribute  other		 ()	{ return (OtherKeyAttribute )get(2); } 
}
