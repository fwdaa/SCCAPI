package aladdin.capi.pkcs11;
import aladdin.capi.*; 
import aladdin.pkcs11.*;
import java.io.*;
import java.util.*;
		
///////////////////////////////////////////////////////////////////////////
// Криптографический контейнер 
///////////////////////////////////////////////////////////////////////////
public class Container extends aladdin.capi.Container
{
    private final long mode;    // режим открытия контейнера

	// конструктор
	public Container(Applet applet, String name, long mode) 
    { 
		// найти смарт-карту контейнера
		super(applet, name); this.mode = mode;
	}
	// криптографический провайдер
	@Override public Provider provider() { return store().provider(); }
    
	// смарт-карта контейнера
	@Override public Applet store() { return (Applet)super.store(); }
    
	// определить идентификаторы ключей
    @Override
	public byte[][] getKeyIDs() throws IOException
    {
        // открыть сеанс
        try (Session session = store().openSession(API.CKS_RO_PUBLIC_SESSION))
        {
            // получить идентификаторы объектов
            return store().getKeyIDs(session, name().toString()); 
        }
    }
    // перечислить все сертификаты
    @Override public aladdin.capi.Certificate[] enumerateAllCertificates() throws IOException
    {
        // открыть сеанс
        try (Session session = store().openSession(API.CKS_RO_PUBLIC_SESSION))
        {
            // перечислить сертификаты
            return store().enumerateAllCertificates(session, name().toString()); 
        }
    }
    // получить цепочку сертификатов
    @Override public aladdin.capi.Certificate[] getCertificateChain(
        aladdin.capi.Certificate certificate) throws IOException
    {
        // перечислить все сертификаты
        aladdin.capi.Certificate[] certificates = enumerateAllCertificates(); 
        
        // получить цепь сертификатов
        return PKI.createCertificateChain(certificate, Arrays.asList(certificates)); 
    }
    @Override
	public final IPublicKey getPublicKey(byte[] keyID) throws IOException
	{ 
        // выделить память для атрибутов поиска
        Attribute[] attributes = new Attribute[] { 

            // указать для поиска тип объекта
            new Attribute(API.CKA_CLASS, API.CKO_PUBLIC_KEY), 

            // указать идентификатор ключа
            new Attribute(API.CKA_ID, keyID)
        }; 
		// открыть сеанс
		try (Session session = store().openSession(API.CKS_RO_PUBLIC_SESSION)) 
		{ 
			// найти открытый ключ
			SessionObject object = session.findTokenObject(
                name().toString(), attributes
            ); 
            // при наличии ключа
            if (object != null) 
            {
                // преобразовать открытый ключ
                IPublicKey publicKey = provider().convertPublicKey(store(), object); 
            
                // проверить поддержку ключа
                if (publicKey != null) return publicKey; 
            
                // при ошибке выбросить исключение
                throw new UnsupportedOperationException(); 
            }
		}
		// получить сертификат
		Certificate certificate = getCertificate(keyID);

		// проверить наличие сертификата
		if (certificate == null) throw new NoSuchElementException();

		// вернуть открытый ключ сертификата
		return certificate.getPublicKey(store().provider()); 
	}
	@Override
	public final IPrivateKey getPrivateKey(byte[] keyID) throws IOException
	{
		// получить открытый ключ
		IPublicKey publicKey = getPublicKey(keyID); 
        
        // выделить память для атрибутов поиска
        Attribute[] privateAtributes = new Attribute[] { 

            // указать для поиска тип объекта
            new Attribute(API.CKA_CLASS, API.CKO_PRIVATE_KEY), 

            // указать идентификатор ключа
            new Attribute(API.CKA_ID, keyID)
        }; 
		// открыть сеанс
        try (Session session = store().openSession(API.CKS_RO_USER_FUNCTIONS)) 
		{ 
			// найти личный ключ
			SessionObject privateObject = session.findTokenObject(
                name().toString(), privateAtributes
            ); 
            // проверить наличие ключа
            if (privateObject == null) throw new NoSuchElementException();  
            
            // преобразовать личный ключ
            IPrivateKey privateKey = provider().convertPrivateKey(
                this, privateObject, publicKey
            ); 
            // проверить поддержку ключа
            if (privateKey != null) return privateKey; 
            
            // при ошибке выбросить исключение
            throw new UnsupportedOperationException(); 
		}
	}
	// получить сертификат открытого ключа
	@Override
	public final Certificate getCertificate(byte[] keyID) throws IOException
	{
        // выделить память для атрибутов поиска
        Attribute[] attributes = new Attribute[] { 

            // указать для поиска тип объекта
            new Attribute(API.CKA_CLASS, API.CKO_CERTIFICATE), 

            // указать идентификатор ключа
            new Attribute(API.CKA_ID, keyID)
        }; 
		// открыть сеанс
		try (Session session = store().openSession(API.CKS_RO_PUBLIC_SESSION)) 
		{ 
            // найти сертификат
            SessionObject object = session.findTokenObject(
                name().toString(), attributes
            ); 
            // проверить наличие открытого ключа
            if (object == null) return null; 
                
            // создать объект сертификата
            try { return new Certificate(object.getValue()); }
            
            // сертификат отсутствует
            catch (Throwable e) {} return null; 
		}
	}
	// сохранить сертификаты открытых ключей
	@Override
	public final void setCertificateChain(byte[] keyID, 
        Certificate[] certificateChain) throws IOException
	{
        // перечислить все сертификаты
        List<Certificate> certificates = Arrays.asList(enumerateCertificates()); 
        
        // создать список добавляемых сертификатов
        List<Certificate> newCertificates = new ArrayList<Certificate>(); 
        
        // добавить целевой сертификат
        newCertificates.add(certificateChain[0]); 
        
        // для всех сертификатов цепочки, кроме целевого
        for (int i = 1; i < certificateChain.length; i++)
        {
            // при отсутствии сертификата добавить сертификат в список
            if (!certificates.contains(certificateChain[i])) newCertificates.add(certificateChain[i]); 
        }
        // указать требуемое состояние сеанса
        long state = (mode == 0) ? API.CKS_RO_USER_FUNCTIONS : API.CKS_RW_USER_FUNCTIONS; 
        
		// открыть сеанс
        try (Session session = store().openSession(state))  
		{ 
            // для всех добавляемых сертификатов
            for (int i = 0; i < newCertificates.size(); i++)
            {
                // указать сертификат
                Certificate certificate = newCertificates.get(i); 

                // выделить память для атрибутов
                List<Attribute> requiredAttributes = new ArrayList<Attribute>();  
                List<Attribute> optionalAttributes = new ArrayList<Attribute>();  

                // указать тип объекта
                requiredAttributes.add(new Attribute(API.CKA_CLASS, API.CKO_CERTIFICATE)); 

                // указать значение сертификата
                requiredAttributes.add(new Attribute(API.CKA_VALUE, certificate.getEncoded())); 
                
                // указать тип сертификата
                optionalAttributes.add(new Attribute(API.CKA_CERTIFICATE_TYPE, API.CKC_X_509));

                // указать субъект сертификата
                optionalAttributes.add(new Attribute(API.CKA_SUBJECT, certificate.subject().encoded()));

                // определить идентификатор сертификата
                if (i == 0) requiredAttributes.add(new Attribute(API.CKA_ID, keyID)); 
                
                // создать сертификат на смарт-карте
                session.createTokenObject(name().toString(), 
                    requiredAttributes.toArray(new Attribute[requiredAttributes.size()]), 
                    optionalAttributes.toArray(new Attribute[optionalAttributes.size()])
                ); 
            }
        }
	}
    // импортировать пару ключей
    @Override public KeyPair importKeyPair(IRand rand, IPublicKey publicKey, 
        IPrivateKey privateKey, KeyUsage keyUsage, KeyFlags keyFlags) throws IOException
	{
        // открыть сеанс
        try (Session session = store().openSession(API.CKS_RW_USER_FUNCTIONS)) 
        {
            // подготовится к записи ключевой пары
            byte[] keyID = store().prepareKeyPair(session, name().toString(), null, rand, keyUsage); 

            // сохранить пару ключей
            SessionObject[] objs = setKeyPair(
                session, keyID, rand, publicKey, privateKey, keyUsage, keyFlags
            ); 
            // преобразовать открытый ключ
            publicKey = provider().convertPublicKey(store(), objs[0]); 
            
            // проверить поддержку ключа
            if (publicKey == null) throw new UnsupportedOperationException(); 
            
            // преобразовать личный ключ
            try (IPrivateKey newPrivateKey = provider().convertPrivateKey(
                this, objs[1], publicKey))
            {
                // проверить поддержку ключа
                if (newPrivateKey == null) throw new UnsupportedOperationException(); 

                // вернуть импортированную пару ключей
                return new KeyPair(publicKey, newPrivateKey, keyID); 
            }
        }
    }
	// сохранить пару ключей
    @Override
	public byte[] setKeyPair(IRand rand, KeyPair keyPair, 
        KeyUsage keyUsage, KeyFlags keyFlags) throws IOException
	{
        // извлечь ключи
        IPublicKey publicKey = keyPair.publicKey; IPrivateKey privateKey = keyPair.privateKey;

        // открыть сеанс
        try (Session session = store().openSession(API.CKS_RW_USER_FUNCTIONS)) 
        {
            // подготовится к записи ключевой пары
            byte[] keyID = store().prepareKeyPair(session, name().toString(), keyPair.keyID, rand, keyUsage); 

            // сохранить пару ключей
            setKeyPair(session, keyID, rand, publicKey, privateKey, keyUsage, keyFlags); return keyID;  
        }
	}
	// сохранить пару ключей
	private SessionObject[] setKeyPair(Session session, byte[] keyID, IRand rand, 
        IPublicKey publicKey, IPrivateKey privateKey, KeyUsage keyUsage, KeyFlags keyFlags) throws IOException
    {
        // получить атрибуты ключей
        Attribute[] publicAttributes = store().provider().publicKeyAttributes(store(), publicKey, null); 
        
        // проверить поддержку ключей
        if (publicAttributes == null) throw new UnsupportedOperationException();
        
        // получить атрибуты ключей
        Attribute[] privateAttributes = store().provider().privateKeyAttributes(store(), privateKey, null); 
        
        // проверить поддержку ключей
        if (privateAttributes == null) throw new UnsupportedOperationException();
        
        // создать списки атрибутов
        List<Attribute> pubAttributes  = new ArrayList<Attribute>(Arrays.asList(publicAttributes )); 
        List<Attribute> privAttributes = new ArrayList<Attribute>(Arrays.asList(privateAttributes)); 
        
        // указать классы объектов
	    pubAttributes .add(new Attribute(API.CKA_CLASS, API.CKO_PUBLIC_KEY ));
        privAttributes.add(new Attribute(API.CKA_CLASS, API.CKO_PRIVATE_KEY));
            
        // указать принадлежность токену
        pubAttributes .add(new Attribute(API.CKA_TOKEN  , API.CK_TRUE));
        privAttributes.add(new Attribute(API.CKA_TOKEN  , API.CK_TRUE));
        privAttributes.add(new Attribute(API.CKA_PRIVATE, API.CK_TRUE));

        // указать имя контейнера
        pubAttributes .add(new Attribute(API.CKA_LABEL, name().toString().getBytes("UTF-8")));
        privAttributes.add(new Attribute(API.CKA_LABEL, name().toString().getBytes("UTF-8")));

        // проверить возможность экспорта
        byte exportable = (keyFlags.equals(KeyFlags.EXPORTABLE)) ? API.CK_TRUE : API.CK_FALSE; 
        
        // указать признак извлекаемости ключа
        privAttributes.add(new Attribute(API.CKA_EXTRACTABLE, exportable));

        // указать идентификатор ключей
        pubAttributes .add(new Attribute(API.CKA_ID, keyID)); 
        privAttributes.add(new Attribute(API.CKA_ID, keyID)); 
            
        // сохранить пару ключей на смарт-карту
        return session.createKeyPair(keyUsage, 
            pubAttributes.toArray (new Attribute[pubAttributes .size()]), 
            privAttributes.toArray(new Attribute[privAttributes.size()]) 
        ); 
    }
	@Override
	public final void deleteKeyPair(byte[] keyID) throws IOException
	{
        // выделить память для атрибутов поиска
		Attribute[] attributes = new Attribute[] { 

            // сохранить идентификатор
            new Attribute(API.CKA_ID, keyID)
        }; 
        // указать требуемое состояние сеанса
        long state = (mode == 0) ? API.CKS_RO_USER_FUNCTIONS : API.CKS_RW_USER_FUNCTIONS; 
        
		// открыть сеанс
        try (Session session = store().openSession(state))  
		{ 
            // перечислить объекты контейнера
            SessionObject[] objects = session.findTokenObjects(name().toString(), attributes); 

            // удалить объекты контейнера
            for (SessionObject obj : objects) session.destroyObject(obj); 
		}
	}
	public final void delete() throws IOException
	{
        // указать требуемое состояние сеанса
        long state = (mode == 0) ? API.CKS_RO_USER_FUNCTIONS : API.CKS_RW_USER_FUNCTIONS; 
        
		// открыть сеанс
        try (Session session = store().openSession(state))  
		{ 
            // перечислить объекты контейнера
            SessionObject[] objects = session.findTokenObjects(name().toString(), null); 

            // удалить все объекты контейнера
            for (SessionObject obj : objects) session.destroyObject(obj); 
		}
	}
};
