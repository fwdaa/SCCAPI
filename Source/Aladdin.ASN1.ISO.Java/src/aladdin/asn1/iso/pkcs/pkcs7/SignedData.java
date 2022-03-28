package aladdin.asn1.iso.pkcs.pkcs7;
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import aladdin.asn1.iso.*; 
import java.io.*; 

//	SignedData ::= SEQUENCE {
//		version								INTEGER,
//		digestAlgorithms					AlgorithmIdentifiers,
//		encapContentInfo					EncapsulatedContentInfo,
//		certificates		[0] IMPLICIT	CertificateSet				OPTIONAL,
//		crls				[1] IMPLICIT	RevocationInfoChoices		OPTIONAL,
//		signerInfos							SignerInfos 
//}

public final class SignedData extends Sequence<IEncodable>
{
    private static final long serialVersionUID = -6930895438239549253L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(Integer                .class).factory(), Cast.N,	Tag.ANY			), 
		new ObjectInfo(new ObjectCreator(AlgorithmIdentifiers	.class).factory(), Cast.N,	Tag.ANY			), 
		new ObjectInfo(new ObjectCreator(EncapsulatedContentInfo.class).factory(), Cast.N,	Tag.ANY			), 
		new ObjectInfo(new ObjectCreator(CertificateSet			.class).factory(), Cast.O,	Tag.context(0)	), 
		new ObjectInfo(new ObjectCreator(RevocationInfoChoices	.class).factory(), Cast.O,	Tag.context(1)	), 
		new ObjectInfo(new ObjectCreator(SignerInfos			.class).factory(), Cast.N,	Tag.ANY			), 
	}; 
	// конструктор при раскодировании
	public SignedData(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public SignedData(Integer version, AlgorithmIdentifiers digestAlgorithms, 
		EncapsulatedContentInfo encapContentInfo, CertificateSet certificates, 
		RevocationInfoChoices crls, SignerInfos signerInfos) 
	{
		super(info, version, digestAlgorithms, encapContentInfo, certificates, crls, signerInfos); 
	}
	public final Integer                    version			() { return (Integer                )get(0); } 
	public final AlgorithmIdentifiers		digestAlgorithms() { return (AlgorithmIdentifiers	)get(1); }
	public final EncapsulatedContentInfo	encapContentInfo() { return (EncapsulatedContentInfo)get(2); } 
	public final CertificateSet             certificates	() { return (CertificateSet			)get(3); }
	public final RevocationInfoChoices      crls			() { return (RevocationInfoChoices	)get(4); } 
	public final SignerInfos				signerInfos		() { return (SignerInfos			)get(5); }
}
