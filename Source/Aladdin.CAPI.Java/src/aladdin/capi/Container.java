package aladdin.capi;
import aladdin.asn1.*;
import aladdin.asn1.iso.*;
import aladdin.asn1.iso.pkix.*;
import aladdin.asn1.iso.pkcs.*;
import aladdin.asn1.iso.pkcs.pkcs7.*;
import java.io.*; 
import java.util.*; 

///////////////////////////////////////////////////////////////////////////
// Криптографический контейнер 
///////////////////////////////////////////////////////////////////////////
public abstract class Container extends SecurityObject implements IClient
{
    // функция фильтра
    public static interface Predicate { boolean test(Container container); }; 
    
	// конструктор
	public Container(ContainerStore store, Object name) { super(store); this.name = name; } 

    // провайдер контейнера
    @Override public CryptoProvider provider() { return store().provider(); }
    // хранилище контейнера
    @Override public ContainerStore store() { return (ContainerStore)super.store(); }
    // имя контейнера
    @Override public final Object name() { return name; } private final Object name; 
    
    // уникальный идентификатор
    @Override public String getUniqueID() throws IOException
    {
        // уникальный идентификатор
        return String.format("%1$s%2$s%3$s", store().getUniqueID(), File.separator, name()); 
    }
	// получить идентификаторы ключей
	public abstract byte[][] getKeyIDs() throws IOException; 
    
	// получить идентификаторы ключей
    public byte[][] getKeyIDs(SubjectPublicKeyInfo publicKeyInfo) throws IOException
    {
        // создать список идентификаторов
        List<byte[]> keyIDs = new ArrayList<byte[]>(); 

        // для всех ключей
        for (byte[] keyID : getKeyIDs())
        {
            // получить сертификат
            Certificate item = getCertificate(keyID); if (item == null) continue; 

            // проверить совпадение открытых ключей
            if (item.publicKeyInfo().equals(publicKeyInfo)) keyIDs.add(keyID); 
        }
        // вернуть список идентификаторов
        return keyIDs.toArray(new byte[0][]); 
    } 
    // получить открытый ключ 
	public abstract IPublicKey getPublicKey(byte[] keyID) throws IOException; 
    
	// получить личный ключ
	public abstract IPrivateKey getPrivateKey(byte[] keyID) throws IOException;
    
    // личный ключ пользователя
    @Override public byte[] getPrivateKey(
        Certificate certificate, Attributes attributes) throws IOException
    {
        // найти соответствующую пару ключей
        byte[] keyID = getKeyPair(certificate); if (keyID == null) return null;

        // получить личный ключ
        try (IPrivateKey privateKey = getPrivateKey(keyID))  
        {
            // закодировать личный ключ
            return privateKey.encode(attributes).encoded(); 
        }
    }
    // все сертификаты контейнера
    public Certificate[] enumerateAllCertificates() throws IOException
    {
        // вернуть сертификаты пользователя
        return enumerateCertificates(); 
    }
    // сертификаты пользователя
    @Override public Certificate[] enumerateCertificates() throws IOException
    {
        // создать список сертификатов пользователя
        List<Certificate> certificates = new ArrayList<Certificate>(); 

        // для всех ключей
        for (byte[] keyID : getKeyIDs())
        { 
            // получить сертификат для ключа
            Certificate certificate = getCertificate(keyID); 

            // при отсутствии сертификата в списке
            if (certificate != null && !certificates.contains(certificate))
            { 
                // добавить сертификат в список
                certificates.add(certificate); 
            }
        }
        // вернуть список сертификатов
        return certificates.toArray(new Certificate[certificates.size()]); 
    }
	// получить сертификат открытого ключа
	public abstract Certificate getCertificate(byte[] keyID) throws IOException; 

	// сохранить сертификат открытого ключа
	public abstract void setCertificate(byte[] keyID, Certificate certificate) 
        throws IOException; 
    
    // найти пару ключей
    public byte[] getKeyPair(Certificate certificate) throws IOException
    {
        // для всех ключей
        for (byte[] keyID : getKeyIDs())
        {
            // получить сертификат для ключа
            Certificate cert = getCertificate(keyID);

            // проверить совпадение сертификатов
            if (cert != null && cert.equals(certificate)) return keyID; 
        }
        return null; 
    }
    // сгенерировать пару ключей
    public final KeyPair generateKeyPair(IRand rand, byte[] keyID, String keyOID, 
        IParameters parameters, KeyUsage keyUsage, KeyFlags keyFlags) throws IOException
    {
	    // получить фабрику кодирования ключей
	    KeyFactory keyFactory = provider().getKeyFactory(keyOID);
        
	    // проверить наличие фабрики
	    if (keyFactory == null) throw new UnsupportedOperationException();

        // получить алгоритм генерации ключей
        try (KeyPairGenerator generator = provider().createGenerator(
            this, rand, keyOID, parameters))
        {  
	        // проверить наличие алгоритма
	        if (generator == null) throw new UnsupportedOperationException();

	        // сгенерировать ключи алгоритма
	        return generator.generate(keyID, keyOID, keyUsage, keyFlags);
        }
    }
    // импортировать пару ключей
	public KeyPair importKeyPair(IRand rand, IPublicKey publicKey, 
        IPrivateKey privateKey, KeyUsage keyUsage, KeyFlags keyFlags) throws IOException
	{
        // указать пару ключей
        try (KeyPair keyPair = new KeyPair(publicKey, privateKey, null))
        {
            // импортировать ключи в контейнер
            byte[] keyID = setKeyPair(rand, keyPair, keyUsage, keyFlags); 

            // получить личный ключ
            try (IPrivateKey privKey = getPrivateKey(keyID))
            { 
                // вернуть импортированную пару ключей
                return new KeyPair(getPublicKey(keyID), privKey, keyID); 
            }
        }
    }
    // сохранить пару ключей
	public abstract byte[] setKeyPair(IRand rand, 
        KeyPair keyPair, KeyUsage keyUsage, KeyFlags keyFlags) throws IOException; 
    
	// удалить пару ключей
	public abstract void deleteKeyPair(byte[] keyID) throws IOException; 

	// удалить все ключи
    public void deleteKeys() throws IOException
    {
        // удалить все ключевые пары
        for (byte[] keyID : getKeyIDs()) deleteKeyPair(keyID);
    }
    // зашифровать данные
    @Override public byte[] encryptData(IRand rand, 
        Certificate certificate, Certificate[] recipientCertificates, 
        CMSData data, Attributes attributes) throws IOException
    {
        // указать идентификатор ключа
        String keyOID = certificate.publicKeyInfo().algorithm().algorithm().value(); 
            
        // найти соответствующую пару ключей
        byte[] keyID = getKeyPair(certificate); 
        
        // проверить наличие пары ключей
        if (keyID == null) throw new NoSuchElementException(); 
        
        // получить личный ключ
        try (IPrivateKey privateKey = getPrivateKey(keyID))  
        {
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
        
        // создать список сертификатов пользователя
        Map<Certificate, byte[]> certificates = new HashMap<Certificate, byte[]>(); 

        // для всех ключей
        for (byte[] keyID : getKeyIDs())
        { 
            // получить сертификат для ключа
            Certificate cert = getCertificate(keyID); 

            // при отсутствии сертификата в списке
            if (cert != null && !certificates.containsKey(cert))
            { 
                // добавить сертификат в список
                certificates.put(cert, keyID); 
            }
        }
        // найти подходящий для расшифрования сертификат
        Certificate certificate = CMS.findCertificate(certificates.keySet(), envelopedData); 

        // проверить наличие сертификата
        if (certificate == null) throw new NoSuchElementException();

        // получить личный ключ
        try (IPrivateKey privateKey = getPrivateKey(certificates.get(certificate)))
        { 
            // расшифровать данные
            return CMS.keyxDecryptData(privateKey, certificate, null, envelopedData);
        }
    }
    // подписать данные
    @Override public byte[] signData(IRand rand, Certificate certificate, CMSData data, 
        Attributes[] authAttributes, Attributes[] unauthAttributes) throws IOException
    {
        // найти соответствующую пару ключей
        byte[] keyID = getKeyPair(certificate); 
        
        // проверить наличие пары ключей
        if (keyID == null) throw new NoSuchElementException();

        // указать идентификатор ключа
        String keyOID = certificate.publicKeyInfo().algorithm().algorithm().value(); 
            
        // получить личный ключ
        try (IPrivateKey privateKey = getPrivateKey(keyID))  
        {
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
}
