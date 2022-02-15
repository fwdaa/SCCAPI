using System;

//	EncryptedData ::= SEQUENCE {
//		version									INTEGER,
//		encryptedContentInfo					EncryptedContentInfo,
//		unprotectedAttrs		[1] IMPLICIT	Attributes				OPTIONAL 
//	}

namespace Aladdin.ASN1.ISO.PKCS.PKCS7
{
	public class EncryptedData : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<Integer				>().Factory(), Cast.N,	Tag.Any			),  
			new ObjectInfo(new ObjectCreator<EncryptedContentInfo	>().Factory(), Cast.N,	Tag.Any			),  
			new ObjectInfo(new ObjectCreator<Attributes			    >().Factory(), Cast.O,	Tag.Context(1)	), 
		}; 
		// конструктор при раскодировании
		public EncryptedData(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public EncryptedData(Integer version, EncryptedContentInfo encryptedContentInfo, 
			Attributes unprotectedAttrs) : 
			base(info, version, encryptedContentInfo, unprotectedAttrs) {}

		public Integer				Version					{ get { return (Integer				)this[0]; } } 
		public EncryptedContentInfo	EncryptedContentInfo	{ get { return (EncryptedContentInfo)this[1]; } }
		public Attributes			UnprotectedAttrs		{ get { return (Attributes			)this[2]; } } 
	}
}
