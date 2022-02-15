using System;

//	CertificationRequestInfo ::= SEQUENCE {
//		version       INTEGER { v1(0) } (v1,...),
//		subject       Name,
//		subjectPKInfo SubjectPublicKeyInfo,
//		attributes    [0] IMPLICIT Attributes
//	}

namespace Aladdin.ASN1.ISO.PKCS.PKCS10
{
	public class CertificationRequestInfo : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<Integer				  >().Factory(0), Cast.N, Tag.Any			), 
			new ObjectInfo(new ChoiceCreator<PKIX.Name				  >().Factory( ), Cast.N, Tag.Any			), 
			new ObjectInfo(new ObjectCreator<PKIX.SubjectPublicKeyInfo>().Factory( ), Cast.N, Tag.Any			), 
			new ObjectInfo(new ObjectCreator<Attributes				  >().Factory( ), Cast.N, Tag.Context(0)	),
		}; 
		// конструктор при раскодировании
		public CertificationRequestInfo(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public CertificationRequestInfo(Integer version, IEncodable subject, 
			PKIX.SubjectPublicKeyInfo subjectPKInfo, Attributes attributes) : 
			base(info, version, subject, subjectPKInfo, attributes) {}

		public Integer					 Version		{ get { return (Integer					 )this[0]; } } 
		public IEncodable				 Subject		{ get { return							  this[1]; } } 
		public PKIX.SubjectPublicKeyInfo SubjectPKInfo	{ get { return (PKIX.SubjectPublicKeyInfo)this[2]; } } 
		public Attributes				 Attributes		{ get { return (Attributes				 )this[3]; } } 
	}
}
