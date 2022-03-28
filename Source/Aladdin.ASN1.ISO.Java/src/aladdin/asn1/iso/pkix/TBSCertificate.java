package aladdin.asn1.iso.pkix;
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import aladdin.asn1.iso.*; 
import java.io.*; 

//	TBSCertificate  ::=  SEQUENCE  {
//		version				 [0] EXPLICIT	INTEGER DEFAULT (0),
//		serialNumber						INTEGER,
//		signature							AlgorithmIdentifier,
//		issuer								Name,
//		validity							Validity,
//		subject								Name,
//		subjectPublicKeyInfo				SubjectPublicKeyInfo,
//		issuerUniqueID		 [1] IMPLICIT	BIT STRING			OPTIONAL,
//		subjectUniqueID		 [2] IMPLICIT	BIT STRING			OPTIONAL,
//		extensions			 [3] EXPLICIT	Extensions			OPTIONAL
//}

public final class TBSCertificate extends Sequence<IEncodable>
{
    private static final long serialVersionUID = -7388801566437996272L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(Integer                .class).factory(), Cast.EO,	Tag.context(0),	new Integer(0)	), 
		new ObjectInfo(new ObjectCreator(Integer                .class).factory(), Cast.N,	Tag.ANY							), 
		new ObjectInfo(new ObjectCreator(AlgorithmIdentifier    .class).factory(), Cast.N,	Tag.ANY							), 
		new ObjectInfo(new ChoiceCreator(Name                   .class).factory(), Cast.N,	Tag.ANY							), 
		new ObjectInfo(new ObjectCreator(Validity               .class).factory(), Cast.N,	Tag.ANY							), 
		new ObjectInfo(new ChoiceCreator(Name                   .class).factory(), Cast.N,	Tag.ANY							), 
		new ObjectInfo(new ObjectCreator(SubjectPublicKeyInfo   .class).factory(), Cast.N,	Tag.ANY							), 
		new ObjectInfo(new ObjectCreator(BitString              .class).factory(), Cast.O,	Tag.context(1)					), 
		new ObjectInfo(new ObjectCreator(BitString              .class).factory(), Cast.O,	Tag.context(2)					), 
		new ObjectInfo(new ObjectCreator(Extensions             .class).factory(), Cast.EO,	Tag.context(3)					), 
	}; 
	// конструктор при раскодировании
	public TBSCertificate(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public TBSCertificate(Integer version, 
		Integer serialNumber, AlgorithmIdentifier signature, 
		IEncodable issuer, Validity validity, IEncodable subject,	
		SubjectPublicKeyInfo subjectPublicKeyInfo, BitString issuerUniqueID, 
		BitString subjectUniqueID, Extensions extensions) 
	{
		super(info, version, serialNumber, signature, issuer, validity, subject, 
			subjectPublicKeyInfo, issuerUniqueID, subjectUniqueID, extensions); 
	}
	public final Integer                version				() { return (Integer                )get(0); } 
	public final Integer                serialNumber		() { return (Integer                )get(1); }
	public final AlgorithmIdentifier	signature			() { return (AlgorithmIdentifier    )get(2); }
	public final IEncodable             issuer				() { return                          get(3); }
	public final Validity				validity			() { return (Validity               )get(4); }
	public final IEncodable             subject				() { return                          get(5); }
	public final SubjectPublicKeyInfo	subjectPublicKeyInfo() { return (SubjectPublicKeyInfo	)get(6); }
	public final BitString              issuerUniqueID		() { return (BitString              )get(7); }
	public final BitString              subjectUniqueID		() { return (BitString              )get(8); }
	public final Extensions             extensions			() { return (Extensions             )get(9); }
    
    // идентификатор сертификата
    public IssuerSerialNumber issuerSerialNumber()
	{ 
		// вернуть идентификатор сертификата
		return new IssuerSerialNumber(issuer(), serialNumber());
	} 
}
