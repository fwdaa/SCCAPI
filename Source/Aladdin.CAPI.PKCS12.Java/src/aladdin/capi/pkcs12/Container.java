package aladdin.capi.pkcs12; 
import aladdin.*; 
import aladdin.asn1.*; 
import aladdin.asn1.Set; 
import aladdin.asn1.iso.*; 
import aladdin.asn1.iso.pkix.*; 
import aladdin.asn1.iso.pkcs.pkcs8.*; 
import aladdin.asn1.iso.pkcs.pkcs12.*; 
import aladdin.capi.*;
import aladdin.capi.pbe.*;
import aladdin.capi.auth.*;
import aladdin.capi.software.*;
import java.io.*;
import java.util.*;

///////////////////////////////////////////////////////////////////////////
// Контейнер PKCS12
///////////////////////////////////////////////////////////////////////////
public class Container extends aladdin.capi.software.Container
{
    // парольная защита
    private final IPBECultureFactory cultureFactory; 
	// контейнер PKCS12 
	private final PfxEncryptedContainer container;

	// открыть существующий контейнер
	public Container(IPBECultureFactory cultureFactory, 
        IRand rand, aladdin.capi.software.ContainerStore store, 
        ContainerStream stream, PFX pfx) throws IOException
	{
		// сохранить переданные параметры
		super(store, stream); this.cultureFactory = RefObject.addRef(cultureFactory); 
        
        // сохранить переданные параметры
        container = new PfxAuthenticatedEncryptedContainer(pfx, store.provider(), rand);
	}
    // освободить выделенные ресурсы
    @Override protected void onClose() throws IOException   
    {
        // освободить выделенные ресурсы
        RefObject.release(container); RefObject.release(cultureFactory); super.onClose(); 
    }
	// содержимое контейнера
	@Override public byte[] encoded() { return container.encoded().encoded(); }
    
    ///////////////////////////////////////////////////////////////////////////
	// Сервис аутентификации
	///////////////////////////////////////////////////////////////////////////
    @Override public AuthenticationService getAuthenticationService(
        String user, Class<? extends Credentials> authenticationType) 
    { 
        // проверить наличие парольной аутентификации
        if (PasswordCredentials.class.isAssignableFrom(authenticationType)) 
        {
            // вернуть сервис аутентификации
            return new PasswordService(this, container); 
        }
        return null; 
    } 
    private boolean ensureAuthenticate()
    {
        // выполнить аутентификацию 
        try { return authenticate().length > 0; } catch (Throwable e) { return false; }
    }
	///////////////////////////////////////////////////////////////////////////
	// Функции поиска по способу использования
	///////////////////////////////////////////////////////////////////////////
	private byte[][] getKeyIDs(KeyUsage keyUsage, boolean set)
	{
		// создать список идентификаторов
		List<byte[]> keyIDs = new ArrayList<byte[]>(); 

		// указать функцию поиска запроса на сертификат
		PfxFilter reqFilter = new ContainerFilter.CertificationRequest(keyUsage, set, false); 
			
		// получить запросы на сертификат
		PfxContainerSafeBag[] reqBags = container.findCertificationRequests(reqFilter); 

        // добавить все идентификаторы запросов на сертификат
        for (PfxContainerSafeBag bag : reqBags) keyIDs.add(bag.id);

		// указать функцию поиска сертификата
		PfxFilter certFilter = new ContainerFilter.Certificate(keyUsage, set, false);  

		// получить сертификаты открытого ключа
		PfxContainerSafeBag[] certBags = container.findCertificates(certFilter); 

        // для всех идентификаторов сертификатов
        for (PfxContainerSafeBag bag : certBags)
        {
            // для всех присутствующих идентификаторов
            boolean find = false; for (byte[] keyID : keyIDs)
            {
                // проверить несовпадение идентификаторов
                if (Arrays.equals(bag.id, keyID)) { find = true; break; }
            }
            // добавить неприсутствующий идентификатор
            if (!find) keyIDs.add(bag.id);
        }
        // проверить нахождение идентификаторов
		if (keyIDs.size() > 0 || set) return keyIDs.toArray(new byte[0][]); 
			
		// указать функцию поиска запроса на сертификат
		reqFilter = new ContainerFilter.CertificationRequest(keyUsage, set, true); 

		// получить запросы на сертификат
		reqBags = container.findCertificationRequests(reqFilter); 

        // для всех идентификаторов запросов
        for (PfxContainerSafeBag bag : reqBags)
        {
            // для всех присутствующих идентификаторов
            boolean find = false; for (byte[] keyID : keyIDs)
            {
                // проверить несовпадение идентификаторов
                if (Arrays.equals(bag.id, keyID)) { find = true; break; }
            }
            // добавить неприсутствующий идентификатор
            if (!find) keyIDs.add(bag.id);
        }
		// указать функцию поиска сертификата
		certFilter = new ContainerFilter.Certificate(keyUsage, set, true);

		// получить сертификаты открытого ключа
		certBags = container.findCertificates(certFilter); 

        // для всех идентификаторов сертификатов
        for (PfxContainerSafeBag bag : certBags)
        {
            // для всех присутствующих идентификаторов
            boolean find = false; for (byte[] keyID : keyIDs)
            {
                // проверить несовпадение идентификаторов
                if (Arrays.equals(bag.id, keyID)) { find = true; break; }
            }
            // добавить неприсутствующий идентификатор
            if (!find) keyIDs.add(bag.id);
        }
		return keyIDs.toArray(new byte[0][]); 
	}
	@Override public byte[][] getKeyIDs()
	{
		// при полном зашифровании данных
		if (container.hasEncryptedItems() && !container.hasDecryptedItems()) 
		{
			// выполнить аутентификацию 
			if (!ensureAuthenticate()) return new byte[0][]; 
		}
		// создать список идентификаторов
		List<byte[]> keyIDs = new ArrayList<byte[]>(); 

		// получить запросы на сертификат
		PfxContainerSafeBag[] reqBags = container.findCertificationRequests(null); 

        // добавить все идентификаторы запросов на сертификат
        for (PfxContainerSafeBag bag : reqBags) keyIDs.add(bag.id);

        // получить сертификаты открытого ключа
		PfxContainerSafeBag[] certBags = container.findCertificates(null); 

        // для всех идентификаторов сертификатов
        for (PfxContainerSafeBag bag : certBags)
        {
            // для всех присутствующих идентификаторов
            boolean find = false; for (byte[] keyID : keyIDs)
            {
                // проверить несовпадение идентификаторов
                if (Arrays.equals(bag.id, keyID)) { find = true; break; }
            }
            // добавить неприсутствующий идентификатор
            if (!find) keyIDs.add(bag.id);
        }
		// получить сертификаты открытого ключа
		PfxContainerSafeBag[] keyBags = container.findPrivateKeys(null); 

        // для всех идентификаторов сертификатов
        for (PfxContainerSafeBag bag : keyBags)
        {
            // для всех присутствующих идентификаторов
            boolean find = false; for (byte[] keyID : keyIDs)
            {
                // проверить несовпадение идентификаторов
                if (Arrays.equals(bag.id, keyID)) { find = true; break; }
            }
            // добавить неприсутствующий идентификатор
            if (!find) keyIDs.add(bag.id);
        }
		return keyIDs.toArray(new byte[0][]); 
	}
	///////////////////////////////////////////////////////////////////////////
	// Функции поиска по открытому ключу
	///////////////////////////////////////////////////////////////////////////
	@Override public byte[][] getKeyIDs(SubjectPublicKeyInfo keyInfo)
	{
		// при полном зашифровании данных
		if (container.hasEncryptedItems() && !container.hasDecryptedItems()) 
		{
			// выполнить аутентификацию 
			if (!ensureAuthenticate()) return new byte[0][]; 
		}
		// создать список идентификаторов
		List<byte[]> keyIDs = new ArrayList<byte[]>(); 

		// указать функцию поиска сертификата
		PfxFilter filter = new ContainerFilter.CertificateInfo(keyInfo); 

		// получить сертификат открытого ключа
		PfxContainerSafeBag[] bags = container.findCertificates(filter); 

        // добавить все идентификаторы сертификатов
        for (PfxContainerSafeBag bag : bags) keyIDs.add(bag.id);

		// при отсутствии сертификатов
		if (keyIDs.isEmpty()) { filter = new ContainerFilter.CertificationRequestInfo(keyInfo); 
			
            // получить запрос на сертификат
            bags = container.findCertificationRequests(filter);

            // добавить все идентификаторы сертификатов
            for (PfxContainerSafeBag bag : bags) keyIDs.add(bag.id);
        }
    	// при отсутствии сертификатов
		if (keyIDs.isEmpty()) { filter = new ContainerFilter.PrivateKeyInfo(provider(), keyInfo); 
			
			// получить личный ключ
			bags = container.findPrivateKeys(filter);

            // добавить все идентификаторы сертификатов
            for (PfxContainerSafeBag bag : bags) keyIDs.add(bag.id);
        }
        return keyIDs.toArray(new byte[0][]);
    }
	///////////////////////////////////////////////////////////////////////////
	// Найти сертификат
	///////////////////////////////////////////////////////////////////////////
    @Override public aladdin.capi.Certificate[] enumerateAllCertificates()
    {
        // создать список сертификатов
		List<aladdin.capi.Certificate> certificates = new ArrayList<aladdin.capi.Certificate>(); 

		// при полном зашифровании данных
		if (container.hasEncryptedItems() && !container.hasDecryptedItems()) 
		{
            // выполнить аутентификацию
            if (!ensureAuthenticate()) return new aladdin.capi.Certificate[0]; 
        }
		// указать функцию поиска сертификатов
		PfxFilter certFilter = new ContainerFilter.Certificate(); 
			
		// получить сертификаты
		PfxContainerSafeBag[] certBags = container.findCertificates(certFilter); 

        // для всех найденных сертификатов
        for (PfxContainerSafeBag bag : certBags)
        try {
	        // извлечь содержимое сертификата
	        CertBag certBag = new CertBag(bag.safeBag.decoded().bagValue()); 

	        // раскодировать сертификат
	        certificates.add(new aladdin.capi.Certificate(certBag.certValue().content())); 
        }
        // вернуть список сертификатов
        catch (Throwable e) {} return certificates.toArray(new aladdin.capi.Certificate[certificates.size()]);
    }
	@Override public aladdin.capi.Certificate getCertificate(byte[] keyID) throws IOException
	{
        PfxSafeBag item; 
        
		// при полном зашифровании данных
		if (container.hasEncryptedItems() && !container.hasDecryptedItems()) 
		{
			// выполнить аутентификацию 
			if (!ensureAuthenticate()) return null; 

            // найти элемент с сертификатом без аутентификации
            item = findCertificateBag(keyID, false); 
        }
        else {
            // найти элемент с сертификатом без аутентификации
            item = findCertificateBag(keyID, false); 

            // найти элемент с сертификатом с аутентификацией
            if (item == null) item = findCertificateBag(keyID, true); 
        }
        // проверить наличие сертификата
        if (item == null) return null; 

	    // извлечь содержимое сертификата
	    CertBag certBag = new CertBag(item.decoded().bagValue()); 

	    // раскодировать сертификат
	    return new aladdin.capi.Certificate(certBag.certValue().content()); 
    }
	private PfxSafeBag findCertificateBag(byte[] keyID, 
        boolean authenticate) throws IOException
	{
		// найти сертификат
		PfxSafeBag item = container.findCertificate(keyID); if (item != null)
        {
            // проверить отсутствие шифрования
            if (item.decoded() != null) return item; 

            // при возможности аутентификации
            else if (authenticate)
            {
                // выполнить аутентификацию
                if (!ensureAuthenticate()) return null; 

                // вызвать функцию повторно
                return findCertificateBag(keyID, false); 
            }
        }
        // закодированный открытый ключ
        SubjectPublicKeyInfo publicKeyInfo = null; 

	    // найти запрос на сертификат
	    if (publicKeyInfo == null && (item = container.findCertificationRequest(keyID)) != null)
        {
            // для незашифрованного элемента
            if (item.decoded() != null)
            {
		        // извлечь содержимое запроса на сертификат 
		        SecretBag secretBag = new SecretBag(item.decoded().bagValue()); 

		        // раскодировать запрос на сертификат
		        publicKeyInfo = new CertificateRequest(secretBag.secretValue().content()).publicKeyInfo(); 
            }
            else if (authenticate)
            {
                // выполнить аутентификацию
                if (!ensureAuthenticate()) return null; 

                // вызвать функцию повторно
                return findCertificateBag(keyID, false); 
            }
        }
		// найти личный ключ
        if (publicKeyInfo == null && (item = container.findPrivateKey(keyID)) != null)
        {
            // для незашифрованного элемента
            if (item.decoded() != null && item.decoded().bagId().value().equals(
                aladdin.asn1.iso.pkcs.pkcs12.OID.BT_KEY))
            {
		        // извлечь содержимое личного ключа
		        PrivateKeyInfo privateKeyInfo = new PrivateKeyInfo(item.decoded().bagValue());

                // pаскодировать пару ключей
                try (KeyPair keyPair = provider().decodeKeyPair(privateKeyInfo))
                {
                    // закодировать открытый ключ
                    publicKeyInfo = keyPair.publicKey.encoded();
                } 
            }
            else if (authenticate)
            {
                // выполнить аутентификацию
                if (!ensureAuthenticate()) return null; 

                // вызвать функцию повторно
                return findCertificateBag(keyID, false); 
            }
        }
        // проверить наличие открытого ключа
        if (publicKeyInfo == null) return null; 
             
		// указать функцию поиска сертификата
		PfxFilter filter = new ContainerFilter.CertificateInfo(publicKeyInfo); 

		// получить сертификат открытого ключа
		PfxContainerSafeBag[] bags = container.findCertificates(filter); 
            
        // вернуть элемент с сертификатом
        return (bags.length != 0) ? bags[0].safeBag : null; 
	}
	///////////////////////////////////////////////////////////////////////////
	// Найти запрос на сертификат
	///////////////////////////////////////////////////////////////////////////
	public CertificateRequest getCertificateRequest(byte[] keyID) throws IOException
	{
        PfxSafeBag item; 
        
		// при полном зашифровании данных
		if (container.hasEncryptedItems() && !container.hasDecryptedItems()) 
		{
			// выполнить аутентификацию 
			if (!ensureAuthenticate()) return null; 

            // найти элемент с запросом на сертификат без аутентификации
            item = findCertificateRequestBag(keyID, false); 
        }
        else {
            // найти элемент с запросом на сертификат без аутентификации
            item = findCertificateRequestBag(keyID, false); 

            // найти элемент с запросом на сертификат без аутентификацией
            if (item == null) item = findCertificateRequestBag(keyID, true); 
        }
        // проверить наличие сертификата
        if (item == null) return null; 

        // извлечь содержимое запроса на сертификат 
        SecretBag secretBag = new SecretBag(item.decoded().bagValue()); 

        // раскодировать запрос на сертификат
        return new CertificateRequest(secretBag.secretValue().content()); 
    }
	private PfxSafeBag findCertificateRequestBag(byte[] keyID, 
        boolean authenticate) throws IOException
	{
	    // найти запрос на сертификат
		PfxSafeBag item = container.findCertificationRequest(keyID); if (item != null)
        {
            // для незашифрованного элемента
            if (item.decoded() != null) return item; 

            // при возможности аутентификации
            else if (authenticate)
            {
                // выполнить аутентификацию
                if (!ensureAuthenticate()) return null; 

                // вызвать функцию повторно
                return findCertificateRequestBag(keyID, false); 
            }
        }
        // закодированный открытый ключ
        SubjectPublicKeyInfo publicKeyInfo = null; 

	    // найти сертификат
	    if (publicKeyInfo == null && (item = container.findCertificate(keyID)) != null)
        {
            // для незашифрованного элемента
            if (item.decoded() != null)
            {
	            // извлечь содержимое сертификата
	            CertBag certBag = new CertBag(item.decoded().bagValue()); 

	            // раскодировать сертификат
	            publicKeyInfo = new aladdin.capi.Certificate(certBag.certValue().content()).publicKeyInfo(); 
            }
            else if (authenticate)
            {
                // выполнить аутентификацию
                if (!ensureAuthenticate()) return null; 

                // вызвать функцию повторно
                return findCertificateRequestBag(keyID, false); 
            }
        }
        // найти личный ключ
        if (publicKeyInfo == null && (item = container.findPrivateKey(keyID)) != null)
        {
            // для незашифрованного элемента
            if (item.decoded() != null &&  item.decoded().bagId().value().equals(
                aladdin.asn1.iso.pkcs.pkcs12.OID.BT_KEY))
            {
			    // извлечь содержимое личного ключа
			    PrivateKeyInfo privateKeyInfo = new PrivateKeyInfo(item.decoded().bagValue());

                // pаскодировать пару ключей
                try (KeyPair keyPair = provider().decodeKeyPair(privateKeyInfo))
                {
                    // закодировать открытый ключ
                    publicKeyInfo = keyPair.publicKey.encoded();
                } 
            }
            else if (authenticate)
            {
                // выполнить аутентификацию
                if (!ensureAuthenticate()) return null; 

                // вызвать функцию повторно
                return findCertificateRequestBag(keyID, false); 
            }
        }
        // проверить наличие открытого ключа
        if (publicKeyInfo == null) return null; 
             
		// указать функцию поиска запроса на сертификат
		PfxFilter filter = new ContainerFilter.CertificationRequestInfo(publicKeyInfo); 

		// получить запрос на сертификат открытого ключа
		PfxContainerSafeBag[] bags = container.findCertificates(filter); 
            
        // вернуть элемент с запросом на сертификат
        return (bags.length != 0) ? bags[0].safeBag : null; 
	}
	///////////////////////////////////////////////////////////////////////////
	// Найти открытый ключ
	///////////////////////////////////////////////////////////////////////////
	@Override public IPublicKey getPublicKey(byte[] keyID) throws IOException
	{
        SubjectPublicKeyInfo publicKeyInfo; 
        
		// при полном зашифровании данных
		if (container.hasEncryptedItems() && !container.hasDecryptedItems()) 
		{
			// выполнить аутентификацию 
			if (!ensureAuthenticate()) return null; 

            // найти содержимое открытого ключа без аутентификации
            publicKeyInfo = getPublicKeyInfo(keyID, false); 
        }
        else {
            // найти содержимое открытого ключа без аутентификации
            publicKeyInfo = getPublicKeyInfo(keyID, false); 

            // найти содержимое открытого ключа с аутентификацией
            if (publicKeyInfo == null) publicKeyInfo = getPublicKeyInfo(keyID, true); 
        }
        // проверить наличие открытого ключа
        if (publicKeyInfo == null) return null; 

        // раскодировать открытый ключ
        return provider().decodePublicKey(publicKeyInfo); 
	}
	private SubjectPublicKeyInfo getPublicKeyInfo(byte[] keyID, 
        boolean authenticate) throws IOException
    {
		// найти сертификат
		PfxSafeBag item = container.findCertificate(keyID); if (item != null)
        {
            // для незашифрованного элемента
            if (item.decoded() != null)
            {
		        // извлечь содержимое сертификата
		        CertBag certBag = new CertBag(item.decoded().bagValue()); 

		        // раскодировать сертификат
		        return new aladdin.capi.Certificate(certBag.certValue().content()).publicKeyInfo(); 
            }
            else if (authenticate)
            {
                // выполнить аутентификацию
                if (!ensureAuthenticate()) return null; 

                // вызвать функцию повторно
                return getPublicKeyInfo(keyID, false); 
            }
        }
		// найти запрос на сертификат
		if ((item = container.findCertificationRequest(keyID)) != null)
        {
            // для незашифрованного элемента
            if (item.decoded() != null)
            {
		        // извлечь содержимое запроса на сертификат 
		        SecretBag secretBag = new SecretBag(item.decoded().bagValue()); 

		        // раскодировать запрос на сертификат
		        return new CertificateRequest(secretBag.secretValue().content()).publicKeyInfo(); 
            }
            else if (authenticate)
            {
                // выполнить аутентификацию
                if (!ensureAuthenticate()) return null; 

                // вызвать функцию повторно
                return getPublicKeyInfo(keyID, false); 
            }
        }
        // найти личный ключ
		if ((item = container.findPrivateKey(keyID)) != null)
        {
            // для незашифрованного элемента
            if (item.decoded() != null && item.decoded().bagId().value().equals(
                aladdin.asn1.iso.pkcs.pkcs12.OID.BT_KEY))
            {
                // извлечь содержимое личного ключа
			    PrivateKeyInfo privateKeyInfo = new PrivateKeyInfo(item.decoded().bagValue());

                // pаскодировать пару ключей
                try (KeyPair keyPair = provider().decodeKeyPair(privateKeyInfo))
                {
                    // закодировать открытый ключ
                    return keyPair.publicKey.encoded();
                } 
            }
            else if (authenticate)
            {
                // выполнить аутентификацию
                if (!ensureAuthenticate())  return null; 

                // вызвать функцию повторно
                return getPublicKeyInfo(keyID, false); 
            }
        }
        return null; 
    }
	///////////////////////////////////////////////////////////////////////////
	// Найти личный ключ
	///////////////////////////////////////////////////////////////////////////
	@Override public IPrivateKey getPrivateKey(byte[] keyID) throws IOException
	{
        PfxSafeBag item; 
        
		// при полном зашифровании данных 
		if (container.hasEncryptedItems() && !container.hasDecryptedItems()) 
        {
            // найти элемент с личным ключом с аутентификацией
            authenticate(); item = findPrivateKeyBag(keyID, false);
        }
        else {
            // найти элемент с личным ключом без аутентификации
            item = findPrivateKeyBag(keyID, false); 

            // найти элемент с личным ключом с аутентификацией
            if (item == null) item = findPrivateKeyBag(keyID, true); 
        }
        // проверить наличие личного ключа
        if (item == null) throw new NoSuchElementException();

        // извлечь содержимое личного ключа
		PrivateKeyInfo privateKeyInfo = new PrivateKeyInfo(item.decoded().bagValue()); 

		// раскодировать ключ
		return provider().decodePrivateKey(privateKeyInfo);
    }
	private PfxSafeBag findPrivateKeyBag(
        byte[] keyID, boolean authenticate) throws IOException
    {
		// получить личный ключ
		PfxSafeBag item = container.findPrivateKey(keyID); if (item == null) return null; 
            
        // для зашифрованного элемента
        if (item.decoded() == null || !item.decoded().bagId().value().equals(
            aladdin.asn1.iso.pkcs.pkcs12.OID.BT_KEY))
        {
            // проверить возможность аутентификации
            if (!authenticate) return null; 
                    
            // выполнить аутентификацию и вызвать функцию повторно
            authenticate(); return findPrivateKeyBag(keyID, false); 
        }
        return item; 
    }
	///////////////////////////////////////////////////////////////////////////
	// Функции установки
	///////////////////////////////////////////////////////////////////////////
	@Override public void setCertificate(byte[] keyID, 
        aladdin.capi.Certificate certificate) throws IOException
	{
		// закодировать сертификат
		CertBag certBag = new CertBag(
			new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs9.OID.CERT_TYPES_X509), 
            new OctetString(certificate.getEncoded())
		); 
		// найти сертификат по идентификатору
		PfxSafeBag item = findCertificateBag(keyID, false); if (item != null) 
		{
			// установить значение сертификата
			item.setValue(new SafeBag(
				new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs12.OID.BT_CERT), 
                certBag, item.decoded().bagAttributes()
			)); 
		}
		// найти запрос по идентификатору
		else if ((item = findCertificateRequestBag(keyID, false)) != null)
        {
			// добавить элемент сертификата
			item.parent().addObject(new PfxData<SafeBag>(new SafeBag(
				new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs12.OID.BT_CERT), 
                certBag, item.decoded().bagAttributes()), null
            )); 
        }
        else {
			// закодировать идентификатор
			OctetString[] encodedID = new OctetString[] { new OctetString(keyID) }; 

			// создать атрибут идентификатора
			Attributes attributes = new Attributes(new Attribute[] { new Attribute(
                new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs9.OID.LOCAL_KEY_ID), 
                new Set<OctetString>(OctetString.class, encodedID)
			)}); 
            // создать элемент для запроса на сертификат
			SafeBag bag = new SafeBag(
                new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs12.OID.BT_CERT), 
                certBag, attributes
            ); 
            // добавить новый элемент в контейнер
            container.addObjects(null, new SafeBag[] { bag }, new PBECulture[] { null }); 
        }
		flush(); 
	}
	@Override public byte[] setKeyPair(IRand rand, 
        KeyPair keyPair, KeyUsage keyUsage, KeyFlags keyFlags) throws IOException
	{
		// закодировать личный ключ
		PrivateKeyInfo privateKeyInfo = keyPair.encode(null); 
        
        // получить идентификатор ключа
        String keyOID = keyPair.publicKey.keyOID(); CertificateRequest request = null; 
        
        // раскодировать открытый ключ
        try (IPrivateKey softPrivateKey = provider().decodePrivateKey(privateKeyInfo)) 
        {
            // создать запрос на сертификат
            request = createCertificationRequest(keyPair.publicKey, softPrivateKey, keyUsage); 
        }
        // закодировать запрос на сертификат
        SecretBag secretBag = new SecretBag(
            new ObjectIdentifier(aladdin.asn1.iso.pkcs.OID.PKCS10), 
            new OctetString(request.getEncoded())
        );
		// выполнить аутентификацию
        byte[] keyID = keyPair.keyID; authenticate(); if (keyID == null)
        {
            // определить идентификаторы ключей
            byte[][] keyIDs = getKeyIDs(keyUsage, true); 
                
            // указать идентификатор ключа
            if (keyIDs.length > 0) { keyID = keyIDs[0]; }
        }
        if (keyID != null)
        {
            // найти сертификат, запрос на сертификат и личный ключ
            PfxSafeBag itemCert = findCertificateBag       (keyID, false);
            PfxSafeBag itemReq  = findCertificateRequestBag(keyID, false);  
            PfxSafeBag itemKey  = findPrivateKeyBag        (keyID, false); 

            // при наличии ключа с запросом в контейнере
            if (itemKey != null && itemReq != null)
            {
                // установить значение ключа
                itemKey.setValue(new SafeBag(
                    new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs12.OID.BT_KEY), 
                    privateKeyInfo, itemKey.decoded().bagAttributes()
                )); 
                // установить значение запроса на сертификат
                itemReq.setValue(new SafeBag(
                    new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs12.OID.BT_SECRET), 
                    secretBag, itemReq.decoded().bagAttributes()
                )); 
            }
            // при наличии в контейнере только ключа
            else if (itemKey != null && itemReq == null)
            {
                // установить значение ключа
                itemKey.setValue(new SafeBag(
                    new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs12.OID.BT_KEY), 
                    privateKeyInfo, itemKey.decoded().bagAttributes()
                )); 
                // добавить значение запроса на сертификат
                container.addChild(itemKey.parent(), null, new SafeBag(
                    new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs12.OID.BT_SECRET), 
                    secretBag, itemKey.decoded().bagAttributes()
                )); 
            }
            // при наличии в контейнере запроса на сертификат
            else if (itemKey == null && itemReq != null)
            {
                // получить тип парольной защиты
                PBECulture culture = cultureFactory.getCulture(rand.window(), keyOID); 
                
                // проверить поддержку защиты
                if (culture == null) throw new UnsupportedOperationException(); 
                
                // добавить значение ключа
                container.addChild(itemReq.parent(), culture, new SafeBag(
                    new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs12.OID.BT_KEY), 
                    privateKeyInfo, itemReq.decoded().bagAttributes()
                )); 
                // установить значение запроса на сертификат
                itemReq.setValue(new SafeBag(
                    new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs12.OID.BT_SECRET), 
                    secretBag, itemReq.decoded().bagAttributes()
                )); 
            }
            // при наличии в контейнере сертификата
            else if (itemKey == null && itemCert != null)
            {
                // получить тип парольной защиты
                PBECulture culture = cultureFactory.getCulture(rand.window(), keyOID); 
                
                // проверить поддержку защиты
                if (culture == null) throw new UnsupportedOperationException(); 

                // добавить значение ключа
                container.addChild(itemCert.parent(), culture, new SafeBag(
                    new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs12.OID.BT_KEY), 
                    privateKeyInfo, itemCert.decoded().bagAttributes()
                )); 
                // установить значение запроса на сертификат
                container.addChild(itemCert.parent(), null, new SafeBag(
                    new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs12.OID.BT_SECRET), 
                    secretBag, itemCert.decoded().bagAttributes()
                )); 
            }
            // удалить сертификат открытого ключа из контейнера
            if (itemCert != null) itemCert.parent().removeObject(itemCert); 
        }
        else {
            // сгенерировать случайный номер
            keyID = new byte[8]; rand.generate(keyID, 0, keyID.length); keyID[0] &= 0x7F;

            // найти сертификат, запрос на сертификат и личный ключ
            PfxSafeBag itemCert = findCertificateBag       (keyID, false);
            PfxSafeBag itemReq  = findCertificateRequestBag(keyID, false);  
            PfxSafeBag itemKey  = findPrivateKeyBag        (keyID, false); 

            // до нахождения свободного слота
            while (itemCert != null || itemReq != null || itemKey != null)
            {
                // сгенерировать случайный номер
                rand.generate(keyID, 0, keyID.length); keyID[0] &= 0x7F;

                // найти сертификат, запрос на сертификат и личный ключ
                itemCert = findCertificateBag       (keyID, false);
                itemReq  = findCertificateRequestBag(keyID, false);  
                itemKey  = findPrivateKeyBag        (keyID, false); 
            }
            // закодировать идентификатор
            OctetString[] encodedID = new OctetString[] { new OctetString(keyID) }; 

            // создать атрибут идентификатора
            Attributes attributes = new Attributes(new Attribute[] { new Attribute(
                new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs9.OID.LOCAL_KEY_ID), 
                new Set<OctetString>(OctetString.class, encodedID)
            )}); 
            // создать элемент для личного ключа
            SafeBag keyBag = new SafeBag(
                new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs12.OID.BT_KEY), 
                privateKeyInfo, attributes
            ); 
            // создать элемент для запроса на сертификат
            SafeBag requestBag = new SafeBag(
                new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs12.OID.BT_SECRET), 
                secretBag, attributes
            ); 
            // получить тип парольной защиты
            PBECulture culture = cultureFactory.getCulture(rand.window(), keyOID); 

            // проверить поддержку защиты
            if (culture == null) throw new UnsupportedOperationException(); 
                
            // добавить новые элементы в контейнер
            container.addObjects(null, new SafeBag[] {keyBag, requestBag}, 
                new PBECulture[] {culture, null}
            ); 
        }
        // вызвать базовую функцию
        flush(); return keyID; 
	}
	@Override public void deleteKeyPair(byte[] keyID) throws IOException
	{ 
		authenticate(); 

		// найти сертификат, запрос на сертификат и личный ключ
		PfxSafeBag itemCert = findCertificateBag       (keyID, false);
		PfxSafeBag itemReq  = findCertificateRequestBag(keyID, false);  
		PfxSafeBag itemKey  = findPrivateKeyBag        (keyID, false); 

		// удалить сертификат открытого ключа из контейнера
		if (itemCert != null) itemCert.parent().removeObject(itemCert); 
		if (itemReq  != null) itemReq .parent().removeObject(itemReq ); 
		if (itemKey  != null) itemKey .parent().removeObject(itemKey ); 

		// вызвать базовую функцию
		super.deleteKeyPair(keyID); 
	}
	///////////////////////////////////////////////////////////////////////////
	// Создать запрос на сертификат
	///////////////////////////////////////////////////////////////////////////
	private CertificateRequest createCertificationRequest(
        IPublicKey publicKey, IPrivateKey privateKey, KeyUsage keyUsage) throws IOException
	{
        // указать идентификатор атрибута
        ObjectIdentifier oid = new ObjectIdentifier(aladdin.asn1.iso.pkix.OID.AT_COMMON_NAME); 
        
        // указать значение атрибута
        PrintableString name = new PrintableString(store().provider().getClass().getName()); 
        
        // указать атрибут отличимого имени
        AttributeTypeValue nameAttribute = new AttributeTypeValue(oid, name); 
        
        // указать отдельное отличимое имя 
        RelativeDistinguishedName rdn = new RelativeDistinguishedName(
            new AttributeTypeValue[] {nameAttribute}
        );
        // указать отличимое имя 
        RelativeDistinguishedNames subject = new RelativeDistinguishedNames(
            new RelativeDistinguishedName[] {rdn}
        ); 
        // получить параметры алгоритма
        AlgorithmIdentifier signParameters = new AlgorithmIdentifier(
            new ObjectIdentifier("2.5.8.0"), null
        ); 
        // создать запрос на сертификат
        return PKI.createCertificationRequest(container.rand(), subject, 
            signParameters, publicKey, privateKey, keyUsage, null, null, null, null
        ); 
	}
}
