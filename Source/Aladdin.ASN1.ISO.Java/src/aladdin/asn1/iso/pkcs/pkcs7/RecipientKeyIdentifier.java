package aladdin.asn1.iso.pkcs.pkcs7;
import aladdin.asn1.*; 
import java.io.*; 

//	RecipientKeyIdentifier ::= SEQUENCE {
//		subjectKeyIdentifier	OCTET STRING,
//		date					GeneralizedTime			OPTIONAL,
//		other					OtherKeyAttribute		OPTIONAL 
//	}

public final class RecipientKeyIdentifier extends Sequence<IEncodable>
{
    private static final long serialVersionUID = -8609637787234167442L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(OctetString		.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(GeneralizedTime	.class).factory(), Cast.O), 
		new ObjectInfo(new ObjectCreator(OtherKeyAttribute  .class).factory(), Cast.O), 
	}; 
	// конструктор при раскодировании
	public RecipientKeyIdentifier(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public RecipientKeyIdentifier(OctetString subjectKeyIdentifier, 
		GeneralizedTime date, OtherKeyAttribute other) 
	{
		super(info, subjectKeyIdentifier, date, other); 
	}
	public final OctetString		subjectKeyIdentifier()	{ return (OctetString		)get(0); } 
	public final GeneralizedTime	date				()	{ return (GeneralizedTime	)get(1); }
	public final OtherKeyAttribute  other				()	{ return (OtherKeyAttribute	)get(2); } 
}
