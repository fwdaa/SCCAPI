using System;

//	SignerInfo ::= SEQUENCE {
//		version								INTEGER,
//		sid									SignerIdentifier,
//		digestAlgorithm						AlgorithmIdentifier,
//		signedAttrs			[0] IMPLICIT	Attributes				OPTIONAL,
//		signatureAlgorithm					AlgorithmIdentifier,
//		signature							OCTET STRING,
//		unsignedAttrs		[1] IMPLICIT	Attributes				OPTIONAL 
//	}

namespace Aladdin.ASN1.ISO.PKCS.PKCS7
{
	public class SignerInfo : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<Integer			>().Factory(), Cast.N,	Tag.Any			), 
			new ObjectInfo(new ChoiceCreator<SignerIdentifier	>().Factory(), Cast.N,	Tag.Any			), 
			new ObjectInfo(new ObjectCreator<AlgorithmIdentifier>().Factory(), Cast.N,	Tag.Any			), 
			new ObjectInfo(new ObjectCreator<Attributes			>().Factory(), Cast.O,	Tag.Context(0)	), 
			new ObjectInfo(new ObjectCreator<AlgorithmIdentifier>().Factory(), Cast.N,	Tag.Any			), 
			new ObjectInfo(new ObjectCreator<OctetString		>().Factory(), Cast.N,	Tag.Any			), 
			new ObjectInfo(new ObjectCreator<Attributes			>().Factory(), Cast.O,	Tag.Context(1)	), 
		}; 
		// конструктор при раскодировании
		public SignerInfo(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public SignerInfo(Integer version, IEncodable sid, 
			AlgorithmIdentifier digestAlgorithm, Attributes signedAttrs, 
			AlgorithmIdentifier signatureAlgorithm, OctetString signature, 
			Attributes unsignedAttrs) : base(info, version, sid, digestAlgorithm, 
			signedAttrs, signatureAlgorithm, signature, unsignedAttrs) {}

		public Integer				Version				{ get { return (Integer				)this[0]; } } 
		public IEncodable			Sid					{ get { return						 this[1]; } }
		public AlgorithmIdentifier	DigestAlgorithm		{ get { return (AlgorithmIdentifier	)this[2]; } } 
		public Attributes			SignedAttrs			{ get { return (Attributes			)this[3]; } }
		public AlgorithmIdentifier	SignatureAlgorithm	{ get { return (AlgorithmIdentifier	)this[4]; } } 
		public OctetString			Signature			{ get { return (OctetString			)this[5]; } }
		public Attributes			UnsignedAttrs		{ get { return (Attributes			)this[6]; } } 
	}
}
