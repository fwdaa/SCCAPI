package aladdin.asn1.iso.pkcs.pkcs7;
import aladdin.asn1.*; 
import aladdin.asn1.Set; 
import aladdin.asn1.iso.pkix.*; 
import java.io.*; 
import java.util.*; 

// RecipientInfos ::= SET SIZE OF RecipientInfo

public final class RecipientInfos extends Set<IEncodable>
{
    private static final long serialVersionUID = 8264260148302910480L;
    
	// конструктор при раскодировании
	public RecipientInfos(IEncodable encodable) throws IOException 
	{
		super(new ChoiceCreator(RecipientInfo.class).factory(), encodable); 
	}
	// конструктор при закодировании
	public RecipientInfos(IEncodable... values) 
	{
		super(new ChoiceCreator(RecipientInfo.class).factory(), values); 
	}
	// найти информацию отдельного пользователя
	public final IEncodable get(Certificate recipientCertificate) throws IOException
    {
        // получить содержимое сертификата
        TBSCertificate tbsCertificate = recipientCertificate.tbsCertificate(); 
        
		// получить идентификатор ключа
		OctetString keyID = (tbsCertificate.extensions() != null) ?
            tbsCertificate.extensions().subjectKeyIdentifier() : null; 
        
        // найти информацию о ключе по идентификатору
		if (keyID != null) { IEncodable recipientInfo = get(keyID);
        
            // вернуть найденную информацию
            if (recipientInfo != null) return recipientInfo; 
        }
        // найти информацию о ключе по идентификатору
        return get(new IssuerSerialNumber(
            tbsCertificate.issuer(), tbsCertificate.serialNumber()
        ));
    }
	// найти информацию отдельного пользователя
	public final IEncodable get(IssuerSerialNumber recipientID) throws IOException
	{
        // для всех получателей
		for (IEncodable recipientInfo : this)
		{
			// в зависимости от типа
			if (recipientInfo.tag().equals(Tag.SEQUENCE))
			{
				// преобразовать тип
				KeyTransRecipientInfo info = new KeyTransRecipientInfo(recipientInfo); 

				// проверить совпадение типа
				if (!info.rid().tag().equals(Tag.SEQUENCE)) continue; 

				// проверить совпадение пользователей
				if (recipientID.equals(info.rid())) return recipientInfo; 
			}
			// в зависимости от типа
			else if (recipientInfo.tag().equals(Tag.context(1)))
			{
				// преобразовать тип
				KeyAgreeRecipientInfo info = new KeyAgreeRecipientInfo(recipientInfo); 
                
              	// проверить совпадение пользователей
                if (info.recipientEncryptedKeys().get(recipientID) != null) return recipientInfo; 
			}
		}
		return null; 
	}
	// найти информацию отдельного пользователя
	public final IEncodable get(OctetString keyID) throws IOException
	{
        // для всех получателей
		for (IEncodable recipientInfo : this)
		{
			// в зависимости от типа
			if (recipientInfo.tag().equals(Tag.SEQUENCE))
			{
				// преобразовать тип
				KeyTransRecipientInfo info = new KeyTransRecipientInfo(recipientInfo); 

				// проверить совпадение типа
				if (!info.rid().tag().equals(Tag.context(0))) continue; 
                
				// проверить совпадение пользователей
				if (Arrays.equals(keyID.value(), info.rid().content())) return recipientInfo; 
			}
			// в зависимости от типа
			else if (recipientInfo.tag().equals(Tag.context(1)))
			{
				// преобразовать тип
				KeyAgreeRecipientInfo info = new KeyAgreeRecipientInfo(recipientInfo); 

              	// проверить совпадение пользователей
                if (info.recipientEncryptedKeys().get(keyID) != null) return recipientInfo; 
			}
			// в зависимости от типа
			else if (recipientInfo.tag().equals(Tag.context(2)))
			{
				// преобразовать тип
				KEKRecipientInfo info = new KEKRecipientInfo(recipientInfo); 

				// проверить совпадение пользователей
				if (keyID.equals(info.kekId().keyIdentifier())) return recipientInfo; 
			}
		}
		return null; 
	}
}
