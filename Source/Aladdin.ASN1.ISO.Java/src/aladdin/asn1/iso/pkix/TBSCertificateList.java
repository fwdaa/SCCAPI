package aladdin.asn1.iso.pkix;
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import aladdin.asn1.iso.*; 
import java.io.*; 

//	TBSCertList  ::=  SEQUENCE  {
//		version							 INTEGER				OPTIONAL,
//		signature						 AlgorithmIdentifier,
//		issuer							 Name,
//		thisUpdate						 Time,
//		nextUpdate						 Time					OPTIONAL,
//		revokedCertificates				 RevokedCertificates	OPTIONAL,
//		crlExtensions       [0] EXPLICIT Extensions				OPTIONAL 
//	}

public final class TBSCertificateList extends Sequence<IEncodable>
{
    private static final long serialVersionUID = -5269271916329372647L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(Integer            .class).factory(), Cast.O,	Tag.ANY			), 
		new ObjectInfo(new ObjectCreator(AlgorithmIdentifier.class).factory(), Cast.N,	Tag.ANY			), 
		new ObjectInfo(new ChoiceCreator(Name				.class).factory(), Cast.N,	Tag.ANY			), 
		new ObjectInfo(new ChoiceCreator(Time				.class).factory(), Cast.N,	Tag.ANY			), 
		new ObjectInfo(new ChoiceCreator(Time				.class).factory(), Cast.O,	Tag.ANY			), 
		new ObjectInfo(new ObjectCreator(RevokedCertificates.class).factory(), Cast.O,	Tag.ANY			), 
		new ObjectInfo(new ObjectCreator(Extensions			.class).factory(), Cast.EO,	Tag.context(0)	), 
	}; 
	// конструктор при раскодировании
	public TBSCertificateList(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public TBSCertificateList(Integer version, 
		AlgorithmIdentifier signature, IEncodable issuer, 
		VisibleString thisUpdate, VisibleString nextUpdate, 
		RevokedCertificates revokedCertificates, Extensions attributes) 
	{
		super(info, version, signature, issuer, thisUpdate, 
			nextUpdate, revokedCertificates, attributes); 
	}
	public final Integer                version				() { return (Integer            )get(0); } 
	public final AlgorithmIdentifier	signature			() { return (AlgorithmIdentifier)get(1); }
	public final IEncodable             issuer				() { return						 get(2); }
	public final VisibleString          thisUpdate			() { return (VisibleString      )get(3); }
	public final VisibleString          nextUpdate			() { return (VisibleString      )get(4); }
	public final RevokedCertificates	revokedCertificates () { return (RevokedCertificates)get(5); }
	public final Extensions             attributes			() { return (Extensions			)get(6); }
}

