using System;

// RecipientInfos ::= SET SIZE OF RecipientInfo

namespace Aladdin.ASN1.ISO.PKCS.PKCS7
{
	public class RecipientInfos : Set
	{
		// конструктор при раскодировании
		public RecipientInfos(IEncodable encodable) : 
			base(new ChoiceCreator<RecipientInfo>().Factory(), encodable) {}

		// конструктор при закодировании
		public RecipientInfos(params IEncodable[] values) : 
			base(new ChoiceCreator<RecipientInfo>().Factory(), values) {}

	    // найти информацию отдельного пользователя
	    public IEncodable this[PKIX.Certificate recipientCertificate] { get 
        {
            // получить содержимое сертификата
            PKIX.TBSCertificate tbsCertificate = recipientCertificate.TBSCertificate; 
        
		    // получить идентификатор ключа
		    OctetString keyID = (tbsCertificate.Extensions != null) ? 
                tbsCertificate.Extensions.SubjectKeyIdentifier : null; 
        
            // найти информацию о ключе по идентификатору
		    if (keyID != null) { IEncodable recipientInfo = this[keyID];
        
                // вернуть найденную информацию
                if (recipientInfo != null) return recipientInfo; 
            }
            // найти информацию о ключе по идентификатору
            return this[new PKIX.IssuerSerialNumber(
                tbsCertificate.Issuer, tbsCertificate.SerialNumber
            )];
        }}
		// найти информацию отдельного пользователя
		public IEncodable this[PKIX.IssuerSerialNumber recipientID] { get
		{
            // для всех получателей
			foreach (IEncodable recipientInfo in this)
			{
				// в зависимости от типа
				if (recipientInfo.Tag == Tag.Sequence)
				{
					// преобразовать тип
					KeyTransRecipientInfo info = new KeyTransRecipientInfo(recipientInfo); 

					// проверить совпадение типа
					if (info.Rid.Tag != Tag.Sequence) continue; 

					// проверить совпадение пользователей
					if (recipientID.Equals(info.Rid)) return recipientInfo; 
				}
				// в зависимости от типа
				else if (recipientInfo.Tag == Tag.Context(1))
				{
					// преобразовать тип
					KeyAgreeRecipientInfo info = new KeyAgreeRecipientInfo(recipientInfo); 

              	    // проверить совпадение пользователей
                    if (info.RecipientEncryptedKeys[recipientID] != null) return recipientInfo; 
				}
			}
			return null; 
		}}
		// найти информацию отдельного пользователя
		public IEncodable this[OctetString keyID] { get 
		{
            // для всех получателей
			foreach (IEncodable recipientInfo in this)
			{
				// в зависимости от типа
				if (recipientInfo.Tag == Tag.Sequence)
				{
					// преобразовать тип
					KeyTransRecipientInfo info = new KeyTransRecipientInfo(recipientInfo); 

					// проверить совпадение типа
					if (info.Rid.Tag != Tag.Context(0)) continue; 

					// проверить совпадение пользователей
					if (Arrays.Equals(keyID.Value, info.Rid.Content)) return recipientInfo; 
				}
				// в зависимости от типа
				else if (recipientInfo.Tag == Tag.Context(1))
				{
					// преобразовать тип
					KeyAgreeRecipientInfo info = new KeyAgreeRecipientInfo(recipientInfo); 

              	    // проверить совпадение пользователей
                    if (info.RecipientEncryptedKeys[keyID] != null) return recipientInfo; 
				}
				// в зависимости от типа
				else if (recipientInfo.Tag == Tag.Context(2))
				{
					// преобразовать тип
					KEKRecipientInfo info = new KEKRecipientInfo(recipientInfo); 

					// проверить совпадение пользователей
					if (keyID.Equals(info.Kekid.KeyIdentifier)) return recipientInfo; 
				}
			}
			return null; 
		}}
	}
}
