package aladdin.capi;
import aladdin.*; 
import aladdin.asn1.*; 
import aladdin.asn1.iso.*; 
import aladdin.asn1.iso.pkcs.*; 
import aladdin.asn1.iso.pkcs.pkcs7.*; 
import java.io.*; 
import java.util.*;

///////////////////////////////////////////////////////////////////////////
// Пользователь ключей
///////////////////////////////////////////////////////////////////////////
public final class Client extends RefObject implements IClient
{
    // сертификаты и личные ключи клиента
    private final Map<Certificate, IPrivateKey> keyPairs; 

	// раскодировать контейнер в памяти
	public Client(aladdin.capi.software.CryptoProvider provider, 
        byte[] encodedStore, String password) throws IOException
	{
        // выделить списки для сертификатов и личных ключей
        keyPairs = new HashMap<Certificate, IPrivateKey>();
        
        // указать поток для обработки
        MemoryStream stream = new MemoryStream(encodedStore);  
        
        // открыть хранилище контейнеров
        try (Container container = provider.openMemoryContainer(stream, "r", password))
        {
            // для всех ключей
            for (byte[] keyID : container.getKeyIDs())
            { 
                // получить сертификат для ключа
                Certificate certificate = container.getCertificate(keyID); 

                // при отсутствии сертификата в списке
                if (certificate != null && !keyPairs.containsKey(certificate))
                { 
                    // добавить личный ключ в список
                    keyPairs.put(certificate, container.getPrivateKey(keyID)); 
                }
            }
        }
        // проверить наличие ключей
        if (keyPairs.isEmpty()) throw new NoSuchElementException();
    }
	// конструктор
	public Client(IPrivateKey privateKey, Certificate certificate)
    {
        // выделить списки для сертификатов и личных ключей
        keyPairs = new HashMap<Certificate, IPrivateKey>(); 
        
        // добавить пару ключей в список
        keyPairs.put(certificate, RefObject.addRef(privateKey)); 
    }
    @Override protected void onClose() throws IOException
    {
        // для всех ключей
        for (IPrivateKey privateKey : keyPairs.values()) 
        {
            // освободить ключ
            RefObject.release(privateKey);
        }
        // вызвать базовую функцию
        super.onClose();
    }
    // уникальный идентификатор
    @Override public String getUniqueID() { return null; }
    
    // сертификаты пользователя
    @Override public Certificate[] enumerateCertificates() 
    { 
        // сертификаты пользователя
        return keyPairs.keySet().toArray(new Certificate[keyPairs.size()]); 
    }
    // личный ключ для шифрования
    @Override public byte[] getPrivateKey(
        Certificate certificate, Attributes attributes) throws IOException
    {
        // найти подходящий личный ключ
        IPrivateKey privateKey = keyPairs.get(certificate); 
        
        // проверить наличие ключа
        if (privateKey == null) return null; 
        
        // закодировать личный ключ
        return privateKey.encode(attributes).encoded(); 
    }
    // зашифровать данные
    @Override public byte[] encryptData(IRand rand, 
        Certificate certificate, Certificate[] recipientCertificates, 
        CMSData data, Attributes attributes) throws IOException
    {
        // найти подходящий личный ключ
        IPrivateKey privateKey = keyPairs.get(certificate); 

        // проверить наличие ключа
        if (privateKey == null) throw new NoSuchElementException(); 
        
        // указать идентификатор ключа
        String keyOID = certificate.publicKeyInfo().algorithm().algorithm().value(); 
        
        // получить алгоритмы по умолчанию
        Culture culture = privateKey.factory().getCulture(privateKey.scope(), keyOID); 
            
        // проверить наличие алгоритмов
        if (culture == null) throw new UnsupportedOperationException(); 
        
        // зашифровать данные
        ContentInfo contentInfo = Culture.keyxEncryptData(culture, rand, 
            privateKey, certificate, recipientCertificates, null, data, attributes
        ); 
        // вернуть зашифрованные данные
        return contentInfo.encoded(); 
    }
    // расшифровать данные на личном ключе
	@Override public CMSData decryptData(byte[] data) throws IOException
    {
    	// интерпретировать данные в формате ContentInfo
		ContentInfo contentInfo = new ContentInfo(Encodable.decode(data));
        
        // проверить тип данных
		if (!contentInfo.contentType().value().equals(
            aladdin.asn1.iso.pkcs.pkcs7.OID.ENVELOPED_DATA)) throw new IOException(); 
        
		// раскодировать данные
		EnvelopedData envelopedData = new EnvelopedData(contentInfo.inner()); 
        
        // найти подходящий для расшифрования сертификат
        Certificate certificate = CMS.findCertificate(keyPairs.keySet(), envelopedData); 

        // проверить наличие сертификата
        if (certificate == null) throw new NoSuchElementException();

        // расшифровать данные
        return CMS.keyxDecryptData(keyPairs.get(certificate), certificate, null, envelopedData); 
    }
    // подписать данные
    @Override public byte[] signData(IRand rand, Certificate certificate, CMSData data, 
        Attributes[] authAttributes, Attributes[] unauthAttributes) throws IOException
    {
        // найти подходящий личный ключ
        IPrivateKey privateKey = keyPairs.get(certificate); 

        // проверить наличие ключа
        if (privateKey == null) throw new NoSuchElementException(); 
        
        // указать идентификатор ключа
        String keyOID = certificate.publicKeyInfo().algorithm().algorithm().value(); 
            
        // получить алгоритмы по умолчанию
        Culture culture = privateKey.factory().getCulture(privateKey.scope(), keyOID); 
            
        // проверить наличие алгоритмов
        if (culture == null) throw new UnsupportedOperationException(); 
        
        // подписать данные
        ContentInfo contentInfo = Culture.signData(culture, rand, 
            privateKey, certificate, data, authAttributes, unauthAttributes
        ); 
        // вернуть подписанные данные
        return contentInfo.encoded(); 
    }
}
