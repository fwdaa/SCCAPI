using System;

//	PFX ::= SEQUENCE {
//		version		INTEGER {v3(3)}(v3,...),
//		authSafe	ContentInfo,
//		macData		MacData			OPTIONAL
//	}

namespace Aladdin.ASN1.ISO.PKCS.PKCS12
{
	public class PFX : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<Integer	>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<ContentInfo>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<MacData	>().Factory(), Cast.O), 
		}; 
		// конструктор при раскодировании
		public PFX(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public PFX(Integer version, ContentInfo authSafe, MacData macData) : 
			base(info, version, authSafe, macData) {}

		public Integer		Version		{ get { return (Integer		)this[0]; } } 
		public ContentInfo	AuthSafe	{ get { return (ContentInfo	)this[1]; } }
		public MacData		MacData		{ get { return (MacData		)this[2]; } }

		public AuthenticatedSafe GetAuthSafeContent() 
		{ 
			// проверить явное указание данных
			if (AuthSafe.ContentType.Value == PKCS7.OID.data) 
			{
				// получить содержимое контейнера
				byte[] encoded = (new OctetString(AuthSafe.Inner)).Value; 

				// вернуть содержимое контейнера
				return new AuthenticatedSafe(Encodable.Decode(encoded)); 
			}
			else {
				// получить содержимое контейнера
				byte[] encoded = (new PKCS7.SignedData(AuthSafe.Inner)).EncapContentInfo.EContent.Value; 

				// вернуть содержимое контейнера
				return new AuthenticatedSafe(Encodable.Decode(encoded)); 
			}
		}
	}
}
