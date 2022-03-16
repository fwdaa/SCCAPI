using System;
using System.Runtime.Serialization;

// SignerInfos ::= SET OF SignerInfo

namespace Aladdin.ASN1.ISO.PKCS.PKCS7
{
	[Serializable]
	public class SignerInfos : Set<SignerInfo>
	{
		// конструктор при сериализации
        protected SignerInfos(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public SignerInfos(IEncodable encodable) : base(encodable) {}

		// конструктор при закодировании
		public SignerInfos(params SignerInfo[] values) : base(values) {}

		// найти информацию отдельного пользователя
		public SignerInfo this[PKIX.IssuerSerialNumber value] { get 
		{
			// для всех подписавших лиц
			foreach (SignerInfo signerInfo in this)
			{
				// проверить совпадение типа
				if (signerInfo.Sid.Tag != Tag.Sequence) continue; 

				// проверить совпадение пользователей
				if (value.Equals(signerInfo.Sid)) return signerInfo; 
			}
			return null; 
		}}
		// найти информацию отдельного пользователя
		public SignerInfo this[OctetString value] { get 
		{
			// для всех подписавших лиц
			foreach (SignerInfo signerInfo in this)
			{
				// проверить совпадение типа
				if (signerInfo.Sid.Tag != Tag.Context(0)) continue; 

				// проверить совпадение пользователей
				if (value.Equals(signerInfo.Sid)) return signerInfo; 
			}
			return null; 
		}}
	}
}
