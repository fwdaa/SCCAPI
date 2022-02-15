package aladdin.asn1.iso.pkcs.pkcs7;
import aladdin.asn1.*; 
import aladdin.asn1.iso.pkix.*; 
import java.io.*; 
import java.util.*; 

// RecipientEncryptedKeys ::= SEQUENCE OF RecipientEncryptedKey

public final class RecipientEncryptedKeys extends Sequence<RecipientEncryptedKey>
{
	// конструктор при раскодировании
	public RecipientEncryptedKeys(IEncodable encodable) throws IOException 
	{
		super(RecipientEncryptedKey.class, encodable); 
	}
	// конструктор при закодировании
	public RecipientEncryptedKeys(RecipientEncryptedKey... values) 
	{
		super(RecipientEncryptedKey.class, values); 
	}
	// найти информацию отдельного пользователя
	public final RecipientEncryptedKey get(Certificate recipientCertificate) throws IOException
    {
        // получить содержимое сертификата
        TBSCertificate tbsCertificate = recipientCertificate.tbsCertificate(); 
        
		// получить идентификатор ключа
		OctetString keyID = (tbsCertificate.extensions() != null) ? 
            tbsCertificate.extensions().subjectKeyIdentifier() : null;  
        
        // найти информацию о ключе по идентификатору
		if (keyID != null) { RecipientEncryptedKey encryptedKey = get(keyID);
        
            // вернуть найденную информацию
            if (encryptedKey != null) return encryptedKey; 
        }
        // найти информацию о ключе по идентификатору
        return get(new IssuerSerialNumber(
            tbsCertificate.issuer(), tbsCertificate.serialNumber()
        ));
    }
	// найти информацию отдельного пользователя
	public final RecipientEncryptedKey get(IssuerSerialNumber recipientIdentifier) 
	{
		// для всех зашифрованных копий
		for (RecipientEncryptedKey encryptedKey : this)
		{
			// проверить совпадение типа
			if (!encryptedKey.rid().tag().equals(Tag.SEQUENCE)) continue; 

			// проверить совпадение пользователей
			if (recipientIdentifier.equals(encryptedKey.rid())) return encryptedKey; 
		}
		return null; 
	}
	// найти информацию отдельного пользователя
	public final RecipientEncryptedKey get(OctetString keyID) throws IOException
	{
		// для всех зашифрованных копий
		for (RecipientEncryptedKey encryptedKey : this)
		{
			// проверить совпадение типа
			if (!encryptedKey.rid().tag().equals(Tag.context(0))) continue;
 
			// преобразовать тип данных
			RecipientKeyIdentifier rid = new RecipientKeyIdentifier(encryptedKey.rid()); 

            // проверить совпадение пользователей
            if (Arrays.equals(keyID.value(), rid.content())) return encryptedKey; 
		}
		return null; 
	}
}
