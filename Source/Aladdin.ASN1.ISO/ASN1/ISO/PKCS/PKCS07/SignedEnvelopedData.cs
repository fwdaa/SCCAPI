using System;
using System.Runtime.Serialization;

//	SignedEnvelopedData ::= SEQUENCE {
//		version									INTEGER,
//		recipientInfos							RecipientInfos,
//		digestAlgorithms						DigestAlgorithms,
//		encryptedContentInfo					EncryptedContentInfo,
//		certificates			[0] IMPLICIT	CertificateSet OPTIONAL,
//		crls					[1] IMPLICIT	RevocationInfoChoices OPTIONAL,
//		signerInfos								SignerInfos 
//	}

namespace Aladdin.ASN1.ISO.PKCS.PKCS7
{
	[Serializable]
	public class SignedEnvelopedData : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<Integer				>().Factory(), Cast.N,	Tag.Any			), 
			new ObjectInfo(new ObjectCreator<RecipientInfos		    >().Factory(), Cast.N,	Tag.Any			), 
			new ObjectInfo(new ObjectCreator<AlgorithmIdentifiers	>().Factory(), Cast.N,	Tag.Any			), 
			new ObjectInfo(new ObjectCreator<EncryptedContentInfo	>().Factory(), Cast.N,	Tag.Any			), 
			new ObjectInfo(new ObjectCreator<CertificateSet		    >().Factory(), Cast.O,	Tag.Context(0)	), 
			new ObjectInfo(new ObjectCreator<RevocationInfoChoices  >().Factory(), Cast.O,	Tag.Context(1)	), 
			new ObjectInfo(new ObjectCreator<SignerInfos			>().Factory(), Cast.N,	Tag.Any			), 
		}; 
		// конструктор при сериализации
        protected SignedEnvelopedData(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public SignedEnvelopedData(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public SignedEnvelopedData(Integer version, RecipientInfos recipientInfos, 
			AlgorithmIdentifiers digestAlgorithms, EncryptedContentInfo encryptedContentInfo, 
			CertificateSet certificates, RevocationInfoChoices crls, SignerInfos signerInfos) : 
			base(info, version, recipientInfos, digestAlgorithms, 
			encryptedContentInfo, certificates, crls, signerInfos) {}

		public Integer					Version					{ get { return (Integer					)this[0]; } } 
		public RecipientInfos			RecipientInfos			{ get { return (RecipientInfos			)this[1]; } }
		public AlgorithmIdentifiers		DigestAlgorithms		{ get { return (AlgorithmIdentifiers	)this[2]; } }
		public EncryptedContentInfo		EncryptedContentInfo	{ get { return (EncryptedContentInfo	)this[3]; } } 
		public CertificateSet			Certificates			{ get { return (CertificateSet			)this[4]; } }
		public RevocationInfoChoices	Crls					{ get { return (RevocationInfoChoices	)this[5]; } } 
		public SignerInfos				SignerInfos				{ get { return (SignerInfos				)this[6]; } }
	}
}
