using System;

//	EnvelopedData ::= SEQUENCE {
//		version									INTEGER,
//		originatorInfo			[0] IMPLICIT	OriginatorInfo			OPTIONAL,
//		recipientInfos							RecipientInfos,
//		encryptedContentInfo					EncryptedContentInfo,
//		unprotectedAttrs		[1] IMPLICIT	Attributes				OPTIONAL 
//	}

namespace Aladdin.ASN1.ISO.PKCS.PKCS7
{
	public class EnvelopedData : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<Integer				>().Factory(), Cast.N,	Tag.Any			), 
			new ObjectInfo(new ObjectCreator<OriginatorInfo		    >().Factory(), Cast.O,	Tag.Context(0)	), 
			new ObjectInfo(new ObjectCreator<RecipientInfos		    >().Factory(), Cast.N,	Tag.Any			), 
			new ObjectInfo(new ObjectCreator<EncryptedContentInfo	>().Factory(), Cast.N,	Tag.Any			), 
			new ObjectInfo(new ObjectCreator<Attributes			    >().Factory(), Cast.O,	Tag.Context(1)	), 
		}; 
		// конструктор при раскодировании
		public EnvelopedData(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public EnvelopedData(Integer version, OriginatorInfo originatorInfo, 
			RecipientInfos recipientInfos, EncryptedContentInfo encryptedContentInfo, 
			Attributes unprotectedAttrs) : 
			base(info, version, originatorInfo, recipientInfos, encryptedContentInfo, unprotectedAttrs) {}

		public Integer				Version					{ get { return (Integer				)this[0]; } } 
		public OriginatorInfo		OriginatorInfo			{ get { return (OriginatorInfo		)this[1]; } }
		public RecipientInfos		RecipientInfos			{ get { return (RecipientInfos		)this[2]; } } 
		public EncryptedContentInfo	EncryptedContentInfo	{ get { return (EncryptedContentInfo)this[3]; } }
		public Attributes			UnprotectedAttrs		{ get { return (Attributes			)this[4]; } }
	}
}
