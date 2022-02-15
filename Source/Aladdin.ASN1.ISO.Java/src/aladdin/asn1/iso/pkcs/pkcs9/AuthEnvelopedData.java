package aladdin.asn1.iso.pkcs.pkcs9;
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import aladdin.asn1.iso.*; 
import aladdin.asn1.iso.pkcs.pkcs7.*; 
import java.io.*;

//	AuthEnvelopedData ::= SEQUENCE {
//		version										INTEGER,
//		originatorInfo				[0] IMPLICIT	OriginatorInfo			OPTIONAL,
//		recipientInfos								RecipientInfos,
//		authEncryptedContentInfo					EncryptedContentInfo,
//		authAttrs					[1] IMPLICIT	Attributes				OPTIONAL,
//		mac											OCTET STRING,
//		unauthAttrs					[2] IMPLICIT	Attributes				OPTIONAL 
//}

public final class AuthEnvelopedData extends Sequence<IEncodable>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(Integer                .class).factory(), Cast.N,	Tag.ANY			), 
		new ObjectInfo(new ObjectCreator(OriginatorInfo         .class).factory(), Cast.O,	Tag.context(0)	), 
		new ObjectInfo(new ObjectCreator(RecipientInfos         .class).factory(), Cast.N,	Tag.ANY			), 
		new ObjectInfo(new ObjectCreator(EncryptedContentInfo	.class).factory(), Cast.N,	Tag.ANY			), 
		new ObjectInfo(new ObjectCreator(Attributes             .class).factory(), Cast.O,	Tag.context(1)	), 
		new ObjectInfo(new ObjectCreator(OctetString            .class).factory(), Cast.N,	Tag.ANY			), 
		new ObjectInfo(new ObjectCreator(Attributes             .class).factory(), Cast.O,	Tag.context(2)	), 
	}; 
	// конструктор при раскодировании
	public AuthEnvelopedData(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public AuthEnvelopedData(Integer version, OriginatorInfo originatorInfo, 
		RecipientInfos recipientInfos, EncryptedContentInfo authEncryptedContentInfo, 
		Attributes authAttrs, OctetString mac, Attributes unauthAttrs) 
	{
		super(info, version, originatorInfo, recipientInfos, 
			authEncryptedContentInfo, authAttrs, mac, unauthAttrs);	
	}
	public final Integer                version					()	{ return (Integer               )get(0); } 
	public final OriginatorInfo         originatorInfo			()	{ return (OriginatorInfo		)get(1); }
	public final RecipientInfos         recipientInfos			()	{ return (RecipientInfos		)get(2); } 
	public final EncryptedContentInfo	authEncryptedContentInfo()	{ return (EncryptedContentInfo	)get(3); } 
	public final Attributes             authAttrs				()	{ return (Attributes			)get(4); }
	public final OctetString            mac						()	{ return (OctetString           )get(5); } 
	public final Attributes             unauthAttrs				()	{ return (Attributes			)get(6); }
}
