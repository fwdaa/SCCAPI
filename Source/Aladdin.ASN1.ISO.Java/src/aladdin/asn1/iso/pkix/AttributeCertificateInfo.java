package aladdin.asn1.iso.pkix;
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import aladdin.asn1.iso.*; 
import java.io.*; 

//	AttributeCertificateInfo ::= SEQUENCE {
//		version					INTEGER,
//		holder					AttributeSubject,
//		issuer					AttributeCertIssuer,
//		signature				AlgorithmIdentifier,
//		serialNumber			INTEGER,
//		attrCertValidityPeriod  AttributeValidity,
//		attributes				Attributes,
//		issuerUniqueID			BIT STRING				OPTIONAL,
//		extensions				Extensions				OPTIONAL
//}

public final class AttributeCertificateInfo extends Sequence<IEncodable>
{
    private static final long serialVersionUID = 2637284305349217201L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(Integer            .class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(AttributeSubject	.class).factory(), Cast.N), 
		new ObjectInfo(new ChoiceCreator(AttributeIssuer	.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(AlgorithmIdentifier.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(Integer            .class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(AttributeValidity	.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(Attributes			.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(BitString          .class).factory(), Cast.O), 
		new ObjectInfo(new ObjectCreator(Extensions			.class).factory(), Cast.O), 
	}; 
	// конструктор при раскодировании
	public AttributeCertificateInfo(IEncodable encodable) throws IOException { super(encodable, info); 
	
		// проверить тип элемента
		if (!issuer().tag().equals(Tag.context(0))) throw new IOException();
	}
	// конструктор при закодировании
	public AttributeCertificateInfo(Integer version, 
		AttributeSubject subject, IEncodable issuer, 
		AlgorithmIdentifier signature, Integer serialNumber, 
		AttributeValidity validity, Attributes attributes, 
		BitString issuerUniqueID, Extensions extensions) 
	{
		super(info, version, subject, issuer, signature, serialNumber, 
			validity, attributes, issuerUniqueID, extensions);  
		
		// проверить тип элемента
		if (!issuer.tag().equals(Tag.context(0))) throw new IllegalArgumentException(); 
	}
	public final Integer                version		  () { return (Integer              )get(0); } 
	public final AttributeSubject       subject		  () { return (AttributeSubject		)get(1); }
	public final IEncodable             issuer		  () { return						 get(2); } 
	public final AlgorithmIdentifier	signature	  () { return (AlgorithmIdentifier	)get(3); }
	public final Integer                serialNumber  () { return (Integer              )get(4); } 
	public final AttributeValidity      validity	  () { return (AttributeValidity	)get(5); }
	public final Attributes             attributes	  () { return (Attributes			)get(6); } 
	public final BitString              issuerUniqueID() { return (BitString            )get(7); }
	public final Extensions             extensions    () { return (Extensions			)get(8); }
}

