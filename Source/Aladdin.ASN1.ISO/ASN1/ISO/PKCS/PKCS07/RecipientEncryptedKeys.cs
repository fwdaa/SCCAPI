using System;

// RecipientEncryptedKeys ::= SEQUENCE OF RecipientEncryptedKey

namespace Aladdin.ASN1.ISO.PKCS.PKCS7
{
	public class RecipientEncryptedKeys : Sequence<RecipientEncryptedKey>
	{
		// конструктор при раскодировании
		public RecipientEncryptedKeys(IEncodable encodable) : base(encodable) {}

		// конструктор при закодировании
		public RecipientEncryptedKeys(params RecipientEncryptedKey[] values) : base(values) {} 

	    // найти информацию отдельного пользователя
	    public RecipientEncryptedKey this[PKIX.Certificate recipientCertificate] { get 
        {
            // получить содержимое сертификата
            PKIX.TBSCertificate tbsCertificate = recipientCertificate.TBSCertificate; 
        
		    // получить идентификатор ключа
		    OctetString keyID = (tbsCertificate.Extensions != null) ? 
                tbsCertificate.Extensions.SubjectKeyIdentifier : null; 
        
            // найти информацию о ключе по идентификатору
		    if (keyID != null) { RecipientEncryptedKey encryptedKey = this[keyID];
        
                // вернуть найденную информацию
                if (encryptedKey != null) return encryptedKey; 
            }
            // найти информацию о ключе по идентификатору
            return this[new PKIX.IssuerSerialNumber(
                tbsCertificate.Issuer, tbsCertificate.SerialNumber
            )];
        }}
		// найти информацию отдельного пользователя
		public RecipientEncryptedKey this[PKIX.IssuerSerialNumber recipientIdentifier] { get 
		{
			// для всех зашифрованных копий
			foreach (RecipientEncryptedKey encryptedKey in this)
			{
				// проверить совпадение типа
				if (encryptedKey.Rid.Tag != Tag.Sequence) continue; 

				// проверить совпадение пользователей
				if (recipientIdentifier.Equals(encryptedKey.Rid)) return encryptedKey; 
			}
			return null; 
		}}
		// найти информацию отдельного пользователя
		public RecipientEncryptedKey this[OctetString keyID] { get 
		{
			// для всех зашифрованных копий
			foreach (RecipientEncryptedKey encryptedKey in this)
			{
				// проверить совпадение типа
				if (encryptedKey.Rid.Tag != Tag.Context(0)) continue;
 
				// преобразовать тип данных
				RecipientKeyIdentifier rid = new RecipientKeyIdentifier(encryptedKey.Rid); 

                // проверить совпадение пользователей
                if (Arrays.Equals(rid.Content, keyID.Value)) return encryptedKey;
			}
			return null; 
		}}
	}
}
