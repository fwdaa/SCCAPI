using System;

//	SignedData ::= SEQUENCE {
//		version								INTEGER,
//		digestAlgorithms					AlgorithmIdentifiers,
//		encapContentInfo					EncapsulatedContentInfo,
//		certificates		[0] IMPLICIT	CertificateSet				OPTIONAL,
//		crls				[1] IMPLICIT	RevocationInfoChoices		OPTIONAL,
//		signerInfos							SignerInfos 
//}

namespace Aladdin.ASN1.ISO.PKCS.PKCS7
{
	public class SignedData : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<Integer				>().Factory(), Cast.N,	Tag.Any			), 
			new ObjectInfo(new ObjectCreator<AlgorithmIdentifiers	>().Factory(), Cast.N,	Tag.Any			), 
			new ObjectInfo(new ObjectCreator<EncapsulatedContentInfo>().Factory(), Cast.N,	Tag.Any			), 
			new ObjectInfo(new ObjectCreator<CertificateSet			>().Factory(), Cast.O,	Tag.Context(0)	), 
			new ObjectInfo(new ObjectCreator<RevocationInfoChoices	>().Factory(), Cast.O,	Tag.Context(1)	), 
			new ObjectInfo(new ObjectCreator<SignerInfos			>().Factory(), Cast.N,	Tag.Any			), 
		}; 
		// конструктор при раскодировании
		public SignedData(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public SignedData(Integer version, AlgorithmIdentifiers digestAlgorithms, 
			EncapsulatedContentInfo encapContentInfo, CertificateSet certificates, 
			RevocationInfoChoices crls, SignerInfos signerInfos) : base(info, version, 
			digestAlgorithms, encapContentInfo, certificates, crls, signerInfos) {}

		public Integer					Version				{ get { return (Integer					)this[0]; } } 
		public AlgorithmIdentifiers		DigestAlgorithms	{ get { return (AlgorithmIdentifiers	)this[1]; } }
		public EncapsulatedContentInfo	EncapContentInfo	{ get { return (EncapsulatedContentInfo	)this[2]; } } 
		public CertificateSet			Certificates		{ get { return (CertificateSet			)this[3]; } }
		public RevocationInfoChoices	Crls				{ get { return (RevocationInfoChoices	)this[4]; } } 
		public SignerInfos				SignerInfos			{ get { return (SignerInfos				)this[5]; } }
	}
}
