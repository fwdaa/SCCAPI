package aladdin.asn1.iso.pkcs.pkcs7;
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import aladdin.asn1.iso.*; 
import java.io.*;

//	EncryptedData ::= SEQUENCE {
//		version									INTEGER,
//		encryptedContentInfo					EncryptedContentInfo,
//		unprotectedAttrs		[1] IMPLICIT	Attributes				OPTIONAL 
//	}

public final class EncryptedData extends Sequence<IEncodable>
{
    private static final long serialVersionUID = -6057583121038721028L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(Integer                .class).factory(), Cast.N,	Tag.ANY			),  
		new ObjectInfo(new ObjectCreator(EncryptedContentInfo	.class).factory(), Cast.N,	Tag.ANY			),  
		new ObjectInfo(new ObjectCreator(Attributes             .class).factory(), Cast.O,	Tag.context(1)	), 
	}; 
	// конструктор при раскодировании
	public EncryptedData(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public EncryptedData(Integer version, 
		EncryptedContentInfo encryptedContentInfo, Attributes unprotectedAttrs) 
	{
		super(info, version, encryptedContentInfo, unprotectedAttrs); 
	}
	public final Integer                version				() { return (Integer                )get(0); } 
	public final EncryptedContentInfo	encryptedContentInfo() { return (EncryptedContentInfo	)get(1); }
	public final Attributes             unprotectedAttrs	() { return (Attributes				)get(2); } 
}
