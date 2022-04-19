package aladdin.capi;
import aladdin.*; 
import aladdin.io.*; 
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
    // сертификаты и цепочки сертификатов
    private final Map<Certificate, Certificate[]> certChains; 

	// раскодировать контейнер в памяти
	public Client(aladdin.capi.software.CryptoProvider provider, 
        byte[] encodedStore, String password) throws IOException
	{
        // выделить списки для сертификатов и личных ключей
        keyPairs = new HashMap<Certificate, IPrivateKey>();
        
        // выделить память для цепочек сертификатов
        certChains = new HashMap<Certificate, Certificate[]>(); 
        
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
                    // получить цепь сертификатов
                    Certificate[] certificateChain = container.getCertificateChain(certificate); 
                        
                    // добавить личный ключ в список
                    keyPairs.put(certificate, container.getPrivateKey(keyID)); 

                    // добавить цепочку сертификатов
                    certChains.put(certificate, certificateChain); 
                }
            }
        }
        // проверить наличие ключей
        if (keyPairs.isEmpty()) throw new NoSuchElementException();
    }
	// конструктор
	public Client(IPrivateKey privateKey, Certificate[] certificateChain)
    {
        // выделить списки для сертификатов и личных ключей
        keyPairs = new HashMap<Certificate, IPrivateKey>(); 
        
        // добавить пару ключей в список
        keyPairs.put(certificateChain[0], RefObject.addRef(privateKey)); 
        
        // выделить память для цепочек сертификатов
        certChains = new HashMap<Certificate, Certificate[]>(); 
        
        // добавить цепочку сертификатов
        certChains.put(certificateChain[0], certificateChain); 
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
    @Override public byte[] encryptData(IRand rand, Culture culture, 
        Certificate certificate, Certificate[] recipientCertificates, 
        CMSData data, Attributes attributes) throws IOException
    {
        // найти подходящий личный ключ
        IPrivateKey privateKey = keyPairs.get(certificate); 

        // проверить наличие ключа
        if (privateKey == null) throw new NoSuchElementException(); 
        
        // найти цепочку сертификатов
        Certificate[] certificateChain = certChains.get(certificate); 
        
        // зашифровать данные
        ContentInfo contentInfo = Culture.keyxEncryptData(
            culture, rand, privateKey, certificateChain, 
            recipientCertificates, null, data, attributes
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
    @Override public byte[] signData(IRand rand, Culture culture, 
        Certificate certificate, CMSData data, 
        Attributes[] authAttributes, Attributes[] unauthAttributes) throws IOException
    {
        // найти подходящий личный ключ
        IPrivateKey privateKey = keyPairs.get(certificate); 

        // проверить наличие ключа
        if (privateKey == null) throw new NoSuchElementException(); 
        
        // найти цепочку сертификатов
        Certificate[] certificateChain = certChains.get(certificate); 
        
        // подписать данные
        ContentInfo contentInfo = Culture.signData(
            culture, rand, privateKey, certificateChain, 
            data, authAttributes, unauthAttributes
        ); 
        // вернуть подписанные данные
        return contentInfo.encoded(); 
    }
}
