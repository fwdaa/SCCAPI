using System;

//	AuthenticatedData ::= SEQUENCE {
//		version							INTEGER,
//		originatorInfo	[0] IMPLICIT	OriginatorInfo			OPTIONAL,
//		recipientInfos					RecipientInfos,
//		macAlgorithm					AlgorithmIdentifier,
//		digestAlgorithm [1] IMPLICIT	AlgorithmIdentifier		OPTIONAL,
//		encapContentInfo				EncapsulatedContentInfo,
//		authAttrs		[2] IMPLICIT	Attributes				OPTIONAL,
//		mac								OCTET STRING,
//		unauthAttrs		[3] IMPLICIT	Attributes				OPTIONAL 
//}

namespace Aladdin.ASN1.ISO.PKCS.PKCS9
{
	public class AuthenticatedData : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<Integer						>().Factory(), Cast.N,	Tag.Any			), 
			new ObjectInfo(new ObjectCreator<PKCS7.OriginatorInfo			>().Factory(), Cast.O,	Tag.Context(0)	), 
			new ObjectInfo(new ObjectCreator<PKCS7.RecipientInfos			>().Factory(), Cast.N,	Tag.Any			), 
			new ObjectInfo(new ObjectCreator<AlgorithmIdentifier			>().Factory(), Cast.N,	Tag.Any			), 
			new ObjectInfo(new ObjectCreator<AlgorithmIdentifier			>().Factory(), Cast.O,	Tag.Context(1)	), 
			new ObjectInfo(new ObjectCreator<PKCS7.EncapsulatedContentInfo  >().Factory(), Cast.N,	Tag.Any			),	
			new ObjectInfo(new ObjectCreator<Attributes					    >().Factory(), Cast.O,	Tag.Context(2)	), 
			new ObjectInfo(new ObjectCreator<OctetString					>().Factory(), Cast.N,	Tag.Any			), 
			new ObjectInfo(new ObjectCreator<Attributes					    >().Factory(), Cast.O,	Tag.Context(3)	), 
		}; 
		// конструктор при раскодировании
		public AuthenticatedData(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public AuthenticatedData(Integer version, PKCS7.OriginatorInfo originatorInfo, 
			PKCS7.RecipientInfos recipientInfos, AlgorithmIdentifier macAlgorithm, 
			AlgorithmIdentifier digestAlgorithm, PKCS7.EncapsulatedContentInfo encapContentInfo, 
			Attributes authAttrs, OctetString mac, Attributes unauthAttrs) : 
			base(info, version, originatorInfo, recipientInfos, macAlgorithm, 
			digestAlgorithm, encapContentInfo, authAttrs, mac, unauthAttrs) {}

		public Integer							Version				{ get { return (Integer							)this[0]; } } 
		public PKCS7.OriginatorInfo				OriginatorInfo		{ get { return (PKCS7.OriginatorInfo			)this[1]; } }
		public PKCS7.RecipientInfos				RecipientInfos		{ get { return (PKCS7.RecipientInfos			)this[2]; } } 
		public AlgorithmIdentifier				MacAlgorithm		{ get { return (AlgorithmIdentifier				)this[3]; } }
		public AlgorithmIdentifier				DigestAlgorithm		{ get { return (AlgorithmIdentifier				)this[4]; } }
		public PKCS7.EncapsulatedContentInfo	EncapContentInfo	{ get { return (PKCS7.EncapsulatedContentInfo	)this[5]; } } 
		public Attributes						AuthAttrs			{ get { return (Attributes						)this[6]; } }
		public OctetString						Mac					{ get { return (OctetString						)this[7]; } } 
		public Attributes						UnauthAttrs			{ get { return (Attributes						)this[8]; } }
	}
}
