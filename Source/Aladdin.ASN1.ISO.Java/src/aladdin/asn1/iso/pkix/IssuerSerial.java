package aladdin.asn1.iso.pkix;
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import java.io.*; 

//	IssuerSerial  ::=  SEQUENCE {
//		issuer    GeneralNames,
//		serial    INTEGER,
//		issuerUID BIT STRING OPTIONAL
//}

public final class IssuerSerial extends Sequence<IEncodable>
{
    private static final long serialVersionUID = -5952176107347545625L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(GeneralNames	.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(Integer        .class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(BitString      .class).factory(), Cast.O), 
	}; 
	// конструктор при раскодировании
	public IssuerSerial(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public IssuerSerial(GeneralNames issuer, 
		Integer serial, BitString issuerUID) 
	{ 
		super(info, issuer, serial, issuerUID); 
	}
	public final GeneralNames	issuer	 () { return (GeneralNames  )get(0); } 
	public final Integer        serial	 () { return (Integer       )get(1); }
	public final BitString      issuerUID() { return (BitString     )get(2); }
}
