using System;

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

namespace Aladdin.ASN1.ISO.PKIX
{
	public class TBSCertificate : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<Integer				>().Factory(), Cast.EO,	Tag.Context(0),	new Integer(0)	), 
			new ObjectInfo(new ObjectCreator<Integer				>().Factory(), Cast.N,	Tag.Any							), 
			new ObjectInfo(new ObjectCreator<AlgorithmIdentifier	>().Factory(), Cast.N,	Tag.Any							), 
			new ObjectInfo(new ChoiceCreator<Name					>().Factory(), Cast.N,	Tag.Any							), 
			new ObjectInfo(new ObjectCreator<Validity				>().Factory(), Cast.N,	Tag.Any							), 
			new ObjectInfo(new ChoiceCreator<Name					>().Factory(), Cast.N,	Tag.Any							), 
			new ObjectInfo(new ObjectCreator<SubjectPublicKeyInfo	>().Factory(), Cast.N,	Tag.Any							), 
			new ObjectInfo(new ObjectCreator<BitString			    >().Factory(), Cast.O,	Tag.Context(1)				 	), 
			new ObjectInfo(new ObjectCreator<BitString			    >().Factory(), Cast.O,	Tag.Context(2)				 	), 
			new ObjectInfo(new ObjectCreator<Extensions			    >().Factory(), Cast.EO,	Tag.Context(3)				 	), 
		}; 
		// конструктор при раскодировании
		public TBSCertificate(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public TBSCertificate(Integer version, Integer serialNumber,
			AlgorithmIdentifier signature, IEncodable issuer, Validity validity, IEncodable subject,							
			SubjectPublicKeyInfo subjectPublicKeyInfo, BitString issuerUniqueID,					
			BitString subjectUniqueID, Extensions extensions) : 
			base(info, version, serialNumber, signature, issuer, validity, subject, 
			subjectPublicKeyInfo, issuerUniqueID, subjectUniqueID, extensions) {}

		public Integer				Version					{ get { return (Integer				)this[0]; } } 
		public Integer				SerialNumber			{ get { return (Integer				)this[1]; } }
		public AlgorithmIdentifier	Signature				{ get { return (AlgorithmIdentifier	)this[2]; } }
		public IEncodable			Issuer					{ get { return					     this[3]; } }
		public Validity				Validity				{ get { return (Validity			)this[4]; } }
		public IEncodable			Subject					{ get { return						 this[5]; } }
		public SubjectPublicKeyInfo	SubjectPublicKeyInfo	{ get { return (SubjectPublicKeyInfo)this[6]; } }
		public BitString			IssuerUniqueID			{ get { return (BitString			)this[7]; } }
		public BitString			SubjectUniqueID			{ get { return (BitString			)this[8]; } }
		public Extensions			Extensions				{ get { return (Extensions			)this[9]; } }

        public ASN1.ISO.PKIX.IssuerSerialNumber IssuerSerialNumber { get 
		{ 
			// вернуть идентификатор сертификата
			return new ASN1.ISO.PKIX.IssuerSerialNumber(Issuer, SerialNumber);
		}} 
	}
}
