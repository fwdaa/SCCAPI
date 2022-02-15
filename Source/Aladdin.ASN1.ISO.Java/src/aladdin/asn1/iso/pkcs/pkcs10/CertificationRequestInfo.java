package aladdin.asn1.iso.pkcs.pkcs10;
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import aladdin.asn1.iso.*; 
import aladdin.asn1.iso.pkix.*; 
import java.io.*;

//	CertificationRequestInfo ::= SEQUENCE {
//		version       INTEGER { v1(0) } (v1,...),
//		subject       Name,
//		subjectPKInfo SubjectPublicKeyInfo,
//		attributes    [0] IMPLICIT Attributes
//	}

public final class CertificationRequestInfo extends Sequence<IEncodable>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(Integer                .class).factory(0), Cast.N,	Tag.ANY			), 
		new ObjectInfo(new ChoiceCreator(Name					.class).factory( ), Cast.N,	Tag.ANY			), 
		new ObjectInfo(new ObjectCreator(SubjectPublicKeyInfo	.class).factory( ), Cast.N, Tag.ANY			), 
		new ObjectInfo(new ObjectCreator(Attributes             .class).factory( ), Cast.N, Tag.context(0)	), 
	}; 
	// конструктор при раскодировании
	public CertificationRequestInfo(IEncodable encodable) throws IOException { super(encodable, info); }  
	
	// конструктор при закодировании
	public CertificationRequestInfo(Integer version, 
		IEncodable subject, SubjectPublicKeyInfo subjectPKInfo, 
		Attributes attributes) 
	{
		super(info, version, subject, subjectPKInfo, attributes); 
	}
	public final Integer                version		 ()	{ return (Integer               )get(0); } 
	public final IEncodable             subject		 () { return						 get(1); } 
	public final SubjectPublicKeyInfo   subjectPKInfo()	{ return (SubjectPublicKeyInfo	)get(2); } 
	public final Attributes             attributes	 () { return (Attributes			)get(3); } 
}
