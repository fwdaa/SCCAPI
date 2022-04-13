package aladdin.capi.jcp;
import aladdin.RefObject;
import aladdin.io.*; 
import aladdin.asn1.*; 
import aladdin.asn1.iso.pkix.*; 
import aladdin.asn1.iso.pkcs.pkcs8.*;
import aladdin.capi.*; 
import aladdin.util.*; 
import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.util.*;

///////////////////////////////////////////////////////////////////////////////
// Криптографический контейнер
///////////////////////////////////////////////////////////////////////////////
public final class KeyStoreSpi extends java.security.KeyStoreSpi implements Closeable
{
	// криптографический провайдер и слот
	private final Provider provider; private final int slot; 
    // криптографический контейнер
    private aladdin.capi.software.Container container; private final String keyOID; 
    
	// конструктор
	public KeyStoreSpi(Provider provider, String keyOID) 
	{ 
		// сохранить переданные параметры
		this.provider = provider; slot = provider.addObject(this); 
        
        // сохранить переданные параметры
        this.keyOID = keyOID; container = null;
	} 
    // освободить выделенные ресурсы
    @Override public void close() throws IOException
    { 
        // закрыть контейнер 
        RefObject.release(container); provider.removeObject(slot); 
    }
	@Override
	public final Date engineGetCreationDate(String name) 
	{
		// операция не поддерживается
		throw new UnsupportedOperationException();
	}
	@Override
	public final void engineLoad(InputStream stream, char[] password) throws IOException 
	{
        // проверить корректность вызова
        if (container != null) throw new IllegalStateException(); 
        
        // проверить корректность параметров
        if (stream == null && password == null) throw new UnsupportedOperationException(); 
        
        // при отсутствии данных 
        if (stream == null) { MemoryStream memoryStream = new MemoryStream();
        
            // создать контейнер PKCS12
            container = provider.createMemoryContainer(memoryStream, new String(password), keyOID); 
        }
        else {
            // выделить динамический буфер
            ByteArrayOutputStream byteStream = new ByteArrayOutputStream(); 

            // прочитать данные во вспомогательный буфер
            byte[] encoded = new byte[4096]; int cb = stream.read(encoded); 

            // до окончания потока
            while (cb == encoded.length)
            {
                // сохранить прочитанные данные
                byteStream.write(encoded); cb = stream.read(encoded); 
            }
            // сохранить прочитанные данные
            byteStream.write(encoded, 0, cb); encoded = byteStream.toByteArray(); 

            // указать используемый поток
            MemoryStream memoryStream = new MemoryStream(encoded);
            
            // открыть контейнер PKCS12
            container = provider.openMemoryContainer(memoryStream, "rw", new String(password)); 
        }
	}
	@Override
	public final void engineStore(OutputStream stream, char[] password) throws IOException
	{
        // проверить корректность вызова
        if (container == null) throw new IllegalStateException(); 
        
		// проверить корректность параметров
		if (stream == null || password != null) throw new UnsupportedOperationException();
        
        // сохранить контейнер в поток
        stream.write(container.encoded());
	}
	@Override
	public final int engineSize() 
    {   
		// определить число элементов
		try { return container.getKeyIDs().length; }
        
        // обработать возможную ошибку
        catch (IOException e) { return 0; }
	}
	@Override
	public final Enumeration<String> engineAliases() 
    { 
		// создать список для имен
		Vector<String> aliases = new Vector<String>(); 
        try {
            // перечислить идентификаторы ключей
            byte[][] keyIDs = container.getKeyIDs(); 

            // для каждого имени
            for (byte[] keyID : keyIDs)  
            {
                // добавить имя в список
                aliases.add(Array.toHexString(keyID));
            }
        }
		// вернуть список имен
        catch (IOException e) {} return aliases.elements();
	}
	@Override
	public final boolean engineContainsAlias(String alias) { 
	try {
        // перечислить идентификаторы ключей
        byte[][] keyIDs = container.getKeyIDs(); 
		
		// закодировать имя элемента
		byte[] encoded = alias.getBytes("UTF-8");  
		
		// для каждого имени
		for (byte[] keyID : keyIDs)
		{
			// проверить совпадение имен
			if (Arrays.equals(keyID, encoded)) return true; 
		}
		return false; 
	}
	// обработать возможную ошибку
	catch (IOException e) { throw new RuntimeException(e); }}

	@Override
	public final boolean engineIsCertificateEntry(String string) { return false; }
	@Override
	public final boolean engineIsKeyEntry(String alias) 
    { 
        // признак наличия ключа
        return engineContainsAlias(alias); 
    }
	@Override
	public final String engineGetCertificateAlias(java.security.cert.Certificate certificate) 
	{
        SubjectPublicKeyInfo publicKeyInfo = null; 
        try {
            // в зависимости от типа сертификата
            if (certificate instanceof X509Certificate)
            {
                // преобразовать тип сертификата
                X509Certificate x509Certificate = (X509Certificate)certificate; 

                // извлечь информацию о подписываемой части сертификата
                aladdin.asn1.iso.pkix.TBSCertificate tbsCertificate = 
                    new aladdin.asn1.iso.pkix.TBSCertificate(
                        Encodable.decode(x509Certificate.getTBSCertificate())
                ); 
                // извлечь информацию об открытом ключе
                publicKeyInfo = tbsCertificate.subjectPublicKeyInfo(); 
            }
            else {
                // раскодировать сертификат
                aladdin.asn1.iso.pkix.Certificate x509Certificate = 
                    new aladdin.asn1.iso.pkix.Certificate(
                        Encodable.decode(certificate.getEncoded())); 

                // извлечь информацию об открытом ключе
                publicKeyInfo = x509Certificate.tbsCertificate().subjectPublicKeyInfo(); 
            }
        }
        // при ошибке выбросить исключение
        catch (CertificateEncodingException e) { throw new RuntimeException(e); }
        catch (IOException                  e) { throw new RuntimeException(e); }
        try {    
            // найти подходящие ключи
            byte[][] keyIDs = container.getKeyIDs(publicKeyInfo); 
            
            // проверить наличие ключей
            if (keyIDs.length == 0) return null; 
            
            // вернуть идентификатор ключа
            return Array.toHexString(keyIDs[0]); 
        }
        // при ошибке выбросить исключение
        catch (IOException e) { throw new RuntimeException(e); }
	}
	@Override
	public final java.security.cert.Certificate[] engineGetCertificateChain(String alias) 
    {
        // получить сертификат
        java.security.cert.Certificate certificate = engineGetCertificate(alias); 
        
        // проверить наличие сертификата
        if (certificate == null) return null; 
        
        // вернуть сертификат
        return new java.security.cert.Certificate[] { certificate }; 
	}
	@Override
	public final java.security.cert.Certificate engineGetCertificate(String alias) {
	try {
		// закодировать имя элемента
		byte[] keyID = alias.getBytes("UTF-8");

		// получить сертификат для ключа
		return container.getCertificate(keyID);
	}
	// обработать возможное исключение
	catch (IOException e) { throw new RuntimeException(e); }}
	
	@Override
	public final void engineSetCertificateEntry(String alias, 
		java.security.cert.Certificate certificate) throws KeyStoreException 
	{
		// доверенные сертификаты не поддерживаются
		throw new KeyStoreException();
	}
	@Override
	public final java.security.Key engineGetKey(String alias, char[] password) 
		throws NoSuchAlgorithmException, UnrecoverableKeyException {
	try {
		// закодировать имя элемента
		byte[] keyID = alias.getBytes("UTF-8"); if (password != null)
		{ 
            // выполнить аутентификацию
            container.setPassword(new String(password)); 
		}
		// получить личный ключ 
		IPrivateKey privateKey = container.getPrivateKey(keyID);
        
        // проверить наличие ключа
        if (privateKey == null) return null; 
			
        // получить открытый ключ
        return container.getPublicKey(keyID); 
	}
	// обработать возможное исключение
	catch (IOException e) { throw new UnrecoverableKeyException(e.getMessage()); }}

	@Override
	public final void engineSetKeyEntry(String alias, byte[] encoded, 
		java.security.cert.Certificate[] certificates) throws KeyStoreException 
    {
        try { 
            // раскодировать личный ключ
            PrivateKeyInfo privateKeyInfo = new PrivateKeyInfo(Encodable.decode(encoded)); 

            // извлечь идентификатор открытого ключа
            String keyOID = privateKeyInfo.privateKeyAlgorithm().algorithm().value(); 

            // получить фабрику кодирования
            aladdin.capi.KeyFactory keyFactory = provider.factory().getKeyFactory(keyOID); 

            // проверить поддержку ключа
            if (keyFactory == null) throw new UnsupportedOperationException(); 

            // раскодировать личный ключ
            try (IPrivateKey privateKey = keyFactory.decodePrivateKey(
                provider.factory(), privateKeyInfo))
            {
                // записать ключевую пару в контейнер
                engineSetKeyEntry(alias, privateKey, null, certificates); 
            }
        }
        // обработать возможное исключение
        catch (IOException e) { throw new KeyStoreException(e.getMessage()); }
	}
	@Override
	public final void engineSetKeyEntry(String alias, java.security.Key key, 
		char[] password, java.security.cert.Certificate[] certificates) throws KeyStoreException {
	try {
        // проверить наличие сертификатов
        if (certificates == null || certificates.length == 0)
        {
            // при ошибке выбросить исключение
            throw new UnsupportedOperationException(); 
        }
		// закодировать имя элемента
		byte[] keyID = alias.getBytes("UTF-8"); if (password != null)
		{ 
            // выполнить аутентификацию
            container.setPassword(new String(password)); 
		}
        // указать начальные условия
        aladdin.capi.Certificate certificate = null; KeyFlags keyFlags = KeyFlags.NONE; 
        try {
            // раскодировать сертификат
            certificate = new aladdin.capi.Certificate(certificates[0].getEncoded()); 
        }
        // при ошибке выбросить исключение
        catch (CertificateEncodingException e) { throw new RuntimeException(e); }
        
        // извлечь открытый ключ
        IPublicKey publicKey = provider.translatePublicKey(certificates[0].getPublicKey()); 
        
        // преобразовать тип личного ключа
        try (IPrivateKey privateKey = provider.translatePrivateKey((java.security.PrivateKey)key))
        {
            // создать пару ключей
            try (aladdin.capi.KeyPair keyPair = new aladdin.capi.KeyPair(publicKey, privateKey, keyID))
            {
                // указать генератор случайных данных
                try (IRand rand = container.provider().createRand(container, null))
                {
                    // записать пару ключей в контейнер
                    keyID = container.setKeyPair(rand, keyPair, certificate.keyUsage(), keyFlags); 
                }
            }
        }
        // записать сертификат в контейнер
        container.setCertificate(keyID, certificate);
	}
	// обработать возможное исключение
	catch (IOException         e) { throw new KeyStoreException(e.getMessage()); }
	catch (InvalidKeyException e) { throw new RuntimeException (e.getMessage()); }}
    
	@Override
	public final void engineDeleteEntry(String alias) throws KeyStoreException {
	try {
		// удалить элемент
		container.deleteKeyPair(alias.getBytes("UTF-8"));  
	}
	// обработать возможное исключение
	catch (IOException e) { throw new KeyStoreException(e.getMessage()); }}
}
