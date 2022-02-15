package aladdin.asn1.iso.pkcs.pkcs7;
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import aladdin.asn1.iso.*; 
import java.io.*;

//	EnvelopedData ::= SEQUENCE {
//		version									INTEGER,
//		originatorInfo			[0] IMPLICIT	OriginatorInfo			OPTIONAL,
//		recipientInfos							RecipientInfos,
//		encryptedContentInfo					EncryptedContentInfo,
//		unprotectedAttrs		[1] IMPLICIT	Attributes				OPTIONAL 
//	}

public final class EnvelopedData extends Sequence<IEncodable>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(Integer                .class).factory(), Cast.N,	Tag.ANY			), 
		new ObjectInfo(new ObjectCreator(OriginatorInfo         .class).factory(), Cast.O,	Tag.context(0)	), 
		new ObjectInfo(new ObjectCreator(RecipientInfos         .class).factory(), Cast.N,	Tag.ANY			), 
		new ObjectInfo(new ObjectCreator(EncryptedContentInfo	.class).factory(), Cast.N,	Tag.ANY			), 
		new ObjectInfo(new ObjectCreator(Attributes             .class).factory(), Cast.O,	Tag.context(1)	), 
	}; 
	// конструктор при раскодировании
	public EnvelopedData(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public EnvelopedData(Integer version, OriginatorInfo originatorInfo, 
		RecipientInfos recipientInfos, EncryptedContentInfo encryptedContentInfo, 
		Attributes unprotectedAttrs) 
	{
		super(info, version, originatorInfo, recipientInfos, encryptedContentInfo, unprotectedAttrs); 
	}
	public final Integer                version				() { return (Integer                )get(0); } 
	public final OriginatorInfo         originatorInfo		() { return (OriginatorInfo			)get(1); }
	public final RecipientInfos         recipientInfos		() { return (RecipientInfos			)get(2); } 
	public final EncryptedContentInfo	encryptedContentInfo() { return (EncryptedContentInfo	)get(3); }
	public final Attributes             unprotectedAttrs	() { return (Attributes				)get(4); }
}
