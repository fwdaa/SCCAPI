using System;
using System.IO;

//	AttributeCertificateInfo ::= SEQUENCE {
//		version					INTEGER,
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
	public class AttributeCertificateInfo : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<Integer			>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<AttributeSubject	>().Factory(), Cast.N), 
			new ObjectInfo(new ChoiceCreator<AttributeCertIssuer>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<AlgorithmIdentifier>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<Integer			>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<AttributeValidity	>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<Attributes			>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<BitString			>().Factory(), Cast.O), 
			new ObjectInfo(new ObjectCreator<Extensions			>().Factory(), Cast.O), 
		}; 
		// конструктор при раскодировании
		public AttributeCertificateInfo(IEncodable encodable) : base(encodable, info) 
		{
			// проверить тип элемента
			if (Issuer.Tag != Tag.Context(0)) throw new InvalidDataException(); 
		}
		// конструктор при закодировании
		public AttributeCertificateInfo(Integer version, AttributeSubject subject, IEncodable issuer, 
			AlgorithmIdentifier signature, Integer serialNumber, AttributeValidity validity, 
			Attributes attributes, BitString issuerUniqueID, Extensions extensions) : 
			base(info, version, subject, issuer, signature, serialNumber, 
			validity, attributes, issuerUniqueID, extensions) 
		{
			// проверить тип элемента
			if (Issuer.Tag != Tag.Context(0)) throw new ArgumentException(); 
		}
		public Integer				Version			{ get { return (Integer				)this[0]; } } 
		public AttributeSubject		Subject			{ get { return (AttributeSubject	)this[1]; } }
		public IEncodable			Issuer			{ get { return						 this[2]; } } 
		public AlgorithmIdentifier	Signature		{ get { return (AlgorithmIdentifier	)this[3]; } }
		public Integer				SerialNumber	{ get { return (Integer				)this[4]; } } 
		public AttributeValidity	Validity		{ get { return (AttributeValidity	)this[5]; } }
		public Attributes			Attributes		{ get { return (Attributes			)this[6]; } } 
		public BitString			IssuerUniqueID	{ get { return (BitString			)this[7]; } }
		public Extensions			Extensions		{ get { return (Extensions			)this[8]; } }
	}
}
