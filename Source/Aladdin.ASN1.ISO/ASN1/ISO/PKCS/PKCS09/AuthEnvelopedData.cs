using System;
using System.Runtime.Serialization;

//	AuthEnvelopedData ::= SEQUENCE {
//		version										INTEGER,
//		originatorInfo				[0] IMPLICIT	OriginatorInfo			OPTIONAL,
//		recipientInfos								RecipientInfos,
//		authEncryptedContentInfo					EncryptedContentInfo,
//		authAttrs					[1] IMPLICIT	Attributes				OPTIONAL,
//		mac											OCTET STRING,
//		unauthAttrs					[2] IMPLICIT	Attributes				OPTIONAL 
//}

namespace Aladdin.ASN1.ISO.PKCS.PKCS9
{
	[Serializable]
	public class AuthEnvelopedData : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<Integer					>().Factory(), Cast.N,	Tag.Any			), 
			new ObjectInfo(new ObjectCreator<PKCS7.OriginatorInfo		>().Factory(), Cast.O,	Tag.Context(0)	), 
			new ObjectInfo(new ObjectCreator<PKCS7.RecipientInfos		>().Factory(), Cast.N,	Tag.Any			), 
			new ObjectInfo(new ObjectCreator<PKCS7.EncryptedContentInfo >().Factory(), Cast.N,	Tag.Any			), 
			new ObjectInfo(new ObjectCreator<Attributes					>().Factory(), Cast.O,	Tag.Context(1)	), 
			new ObjectInfo(new ObjectCreator<OctetString				>().Factory(), Cast.N,	Tag.Any			), 
			new ObjectInfo(new ObjectCreator<Attributes					>().Factory(), Cast.O,	Tag.Context(2)	), 
		}; 
		// конструктор при сериализации
        protected AuthEnvelopedData(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public AuthEnvelopedData(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public AuthEnvelopedData(Integer version, PKCS7.OriginatorInfo originatorInfo, 
			PKCS7.RecipientInfos recipientInfos, PKCS7.EncryptedContentInfo authEncryptedContentInfo, 
			Attributes authAttrs, OctetString mac, Attributes unauthAttrs) : 
			base(info, version, originatorInfo, recipientInfos, 
			authEncryptedContentInfo, authAttrs, mac, unauthAttrs) {}

		public Integer						Version						{ get { return (Integer						)this[0]; } } 
		public PKCS7.OriginatorInfo			OriginatorInfo				{ get { return (PKCS7.OriginatorInfo		)this[1]; } }
		public PKCS7.RecipientInfos			RecipientInfos				{ get { return (PKCS7.RecipientInfos		)this[2]; } } 
		public PKCS7.EncryptedContentInfo	AuthEncryptedContentInfo	{ get { return (PKCS7.EncryptedContentInfo	)this[3]; } } 
		public Attributes					AuthAttrs					{ get { return (Attributes					)this[4]; } }
		public OctetString					Mac							{ get { return (OctetString					)this[5]; } } 
		public Attributes					UnauthAttrs					{ get { return (Attributes					)this[6]; } }
	}
}
