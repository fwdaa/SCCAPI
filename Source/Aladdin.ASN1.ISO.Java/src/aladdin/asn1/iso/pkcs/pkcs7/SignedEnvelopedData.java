package aladdin.asn1.iso.pkcs.pkcs7;
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import aladdin.asn1.iso.*; 
import java.io.*; 

//	SignedEnvelopedData ::= SEQUENCE {
//		version									INTEGER,
//		recipientInfos							RecipientInfos,
//		digestAlgorithms						DigestAlgorithms,
//		encryptedContentInfo					EncryptedContentInfo,
//		certificates			[0] IMPLICIT	CertificateSet OPTIONAL,
//		crls					[1] IMPLICIT	RevocationInfoChoices OPTIONAL,
//		signerInfos								SignerInfos 
//	}

public final class SignedEnvelopedData extends Sequence<IEncodable>
{
    private static final long serialVersionUID = -7793897647141733672L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(Integer                .class).factory(), Cast.N,	Tag.ANY			), 
		new ObjectInfo(new ObjectCreator(RecipientInfos         .class).factory(), Cast.N,	Tag.ANY			), 
		new ObjectInfo(new ObjectCreator(AlgorithmIdentifiers	.class).factory(), Cast.N,	Tag.ANY			), 
		new ObjectInfo(new ObjectCreator(EncryptedContentInfo	.class).factory(), Cast.N,	Tag.ANY			), 
		new ObjectInfo(new ObjectCreator(CertificateSet         .class).factory(), Cast.O,	Tag.context(0)	), 
		new ObjectInfo(new ObjectCreator(RevocationInfoChoices  .class).factory(), Cast.O,	Tag.context(1)	), 
		new ObjectInfo(new ObjectCreator(SignerInfos			.class).factory(), Cast.N,	Tag.ANY			), 
	}; 
	// конструктор при раскодировании
	public SignedEnvelopedData(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public SignedEnvelopedData(Integer version, 
		RecipientInfos recipientInfos, AlgorithmIdentifiers digestAlgorithms, 
		EncryptedContentInfo encryptedContentInfo, CertificateSet certificates, 
		RevocationInfoChoices crls, SignerInfos signerInfos) 
	{
		super(info, version, recipientInfos, digestAlgorithms, 
			encryptedContentInfo, certificates, crls, signerInfos); 	
	}
	public final Integer                version				() { return (Integer                )get(0); } 
	public final RecipientInfos			recipientInfos		() { return (RecipientInfos			)get(1); }
	public final AlgorithmIdentifiers	digestAlgorithms	() { return (AlgorithmIdentifiers	)get(2); }
	public final EncryptedContentInfo	encryptedContentInfo() { return (EncryptedContentInfo	)get(3); } 
	public final CertificateSet			certificates		() { return (CertificateSet			)get(4); }
	public final RevocationInfoChoices	crls				() { return (RevocationInfoChoices	)get(5); } 
	public final SignerInfos			signerInfos			() { return (SignerInfos			)get(6); }
}
