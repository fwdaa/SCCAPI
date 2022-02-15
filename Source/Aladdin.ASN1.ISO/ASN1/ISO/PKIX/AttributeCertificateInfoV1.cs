using System;
using System.IO;

//	AttributeCertificateInfoV1 ::= SEQUENCE {
//		version					INTEGER					DEFAULT (0),
//		holder					AttributeSubject,
//		issuer					AttributeCertIssuer,
//		signature				AlgorithmIdentifier,
//		serialNumber			INTEGER,
//		attrCertValidityPeriod  AttributeValidity,
//		attributes				Attributes,
//		issuerUniqueID			BIT STRING				OPTIONAL,
//		extensions				Extensions				OPTIONAL
//}

namespace Aladdin.ASN1.ISO.PKIX
{
	public class AttributeCertificateInfoV1 : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<Integer			>().Factory(), Cast.N,	Tag.Any, new Integer(0)	), 
			new ObjectInfo(new ObjectCreator<AttributeSubject	>().Factory(), Cast.N,	Tag.Any					), 
			new ObjectInfo(new ChoiceCreator<AttributeCertIssuer>().Factory(), Cast.N,	Tag.Any					), 
			new ObjectInfo(new ObjectCreator<AlgorithmIdentifier>().Factory(), Cast.N,	Tag.Any					), 
			new ObjectInfo(new ObjectCreator<Integer			>().Factory(), Cast.N,	Tag.Any					), 
			new ObjectInfo(new ObjectCreator<AttributeValidity	>().Factory(), Cast.N,	Tag.Any					), 
			new ObjectInfo(new ObjectCreator<Attributes			>().Factory(), Cast.N,	Tag.Any					), 
			new ObjectInfo(new ObjectCreator<BitString			>().Factory(), Cast.O,	Tag.Any					), 
			new ObjectInfo(new ObjectCreator<Extensions			>().Factory(), Cast.O,	Tag.Any					), 
		}; 
		// конструктор при раскодировании
		public AttributeCertificateInfoV1(IEncodable encodable) : base(encodable, info) 
		{
			// проверить отсутствие поля
			if (Subject.ObjectDigestInfo != null) throw new InvalidDataException(); 
		}
		// конструктор при закодировании
		public AttributeCertificateInfoV1(Integer version, AttributeSubject subject, IEncodable issuer, 
			AlgorithmIdentifier signature, Integer serialNumber, AttributeValidity validity, 
			Attributes attributes, BitString issuerUniqueID, Extensions extensions) : 
			base(info, version, subject, issuer, signature, serialNumber, validity, 
			attributes, issuerUniqueID, extensions) 
		{
			// проверить отсутствие поля
			if (Subject.ObjectDigestInfo != null) throw new ArgumentException(); 
		}
		public Integer				Version			 { get { return (Integer			)this[0]; } } 
		public AttributeSubject		Subject			 { get { return (AttributeSubject	)this[1]; } }
		public IEncodable			Issuer			 { get { return						 this[2]; } } 
		public AlgorithmIdentifier	Signature		 { get { return (AlgorithmIdentifier)this[3]; } }
		public Integer				SerialNumber	 { get { return (Integer			)this[4]; } } 
		public AttributeValidity	Validity		 { get { return (AttributeValidity	)this[5]; } }
		public Attributes			Attributes		 { get { return (Attributes			)this[6]; } } 
		public BitString			IssuerUniqueID	 { get { return (BitString			)this[7]; } }
		public Extensions			Extensions		 { get { return (Extensions			)this[8]; } }
	}
}
