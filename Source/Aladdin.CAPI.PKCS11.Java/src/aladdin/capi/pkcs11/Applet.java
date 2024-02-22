package aladdin.capi.pkcs11;
import aladdin.RefObject;
import aladdin.capi.*;
import aladdin.capi.auth.*;
import aladdin.pkcs11.*; 
import aladdin.util.*; 
import java.util.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Апплет на аппаратном устройстве
///////////////////////////////////////////////////////////////////////////////
public class Applet extends ContainerStore implements IRandFactory
{
    // идентификатор слота, имя апплета и список алгоритмов
    private final long slotID; private final String name; private final List<Long> algIDs; 

	// конструктор
	public Applet(Token token, long slotID) throws IOException
	{
        // получить информацию устройства
        super(token); this.slotID = slotID; name = getInfo().model(); algIDs = new ArrayList<Long>();
        
        // заполнить список алгоритмов
        for (long algID : module().getAlgorithmList(slotID)) algIDs.add(algID); 
	}
	// интерфейс вызова функций
	public final Module module() { return provider().module(); } 
    
	///////////////////////////////////////////////////////////////////////////
	// Атрибуты устройства
	///////////////////////////////////////////////////////////////////////////
	@Override public final Provider	provider() { return store().provider(); }
    
    // смарт-карта апплета
	@Override public final Token store() { return (Token)super.store(); }
    
    // имя апплета
    @Override public String name() { return name; }
    
    // получить информацию апплета
	public final TokenInfo getInfo() throws IOException
    { 
        // получить информацию апплета
        return module().getTokenInfo(slotID);	  
    }
    // уникальный идентификатор
    @Override public String getUniqueID() throws IOException
    {
        // получить серийный номер апплета
        String serial = Array.toHexString(getInfo().serialNumber()); 
        
        // вернуть уникальный идентификатор
        return String.format("%1$s%2$s%3$s", 
            super.getUniqueID(), File.separator, serial
        ); 
    }
	///////////////////////////////////////////////////////////////////////////
	// Аутентификация устройства
	///////////////////////////////////////////////////////////////////////////

    // поддерживаемые типы аутентификации
    @Override @SuppressWarnings({"unchecked"})
	public Class<? extends Credentials>[] getAuthenticationTypes(String user)
    { 
        // создать список поддерживаемых аутентификаций
        Object authenticationTypes = java.lang.reflect.Array.newInstance(Class.class, 1); 
        
        // поддерживается парольная аутентификация
        java.lang.reflect.Array.set(authenticationTypes, 0, PasswordCredentials.class); 
        
        // вернуть список поддерживаемых аутентификаций
        return (Class<? extends Credentials>[])authenticationTypes;
    } 
    // получить сервис аутентификации
	@Override public AuthenticationService getAuthenticationService(
		String user, Class<? extends Credentials> authenticationType)
    {
        // проверить наличие парольной аутентификации
        if (!PasswordCredentials.class.isAssignableFrom(authenticationType)) return null;   

        // вернуть сервис аутентификации
        return new PasswordService(this, user); 
    }
	// аутентификация устройства
	public void setPassword(String user, String password) throws IOException
	{
		// указать парольную аутентификацию
		Authentication authentication = new PasswordCredentials(user, password);

		// установить и выполнить аутентификацию
		setAuthentication(authentication); authenticate();
	}
	// создать сеанс
	public Session openSession(long state) throws IOException
	{ 
        // указать тип пользователя
        String user = (state == API.CKS_RW_SO_FUNCTIONS) ? "ADMIN" : "USER"; 
        
        // получить кэш аутентификации
        CredentialsManager cache = ExecutionContext.getProviderCache(provider().name()); 
        
        // скорректировать режим открытия 
        long mode = (state == API.CKS_RO_PUBLIC_SESSION || 
            state == API.CKS_RO_USER_FUNCTIONS) ? 0 : API.CKF_RW_SESSION; 
        
		// создать сеанс
		try (Session session = new Session(module(), slotID, mode, null, null))
        {
            // получить состояние сеанса
            long sessionState = session.getSessionInfo().state(); 
            
            // при необходимости аутентификации
            if (state != API.CKS_RO_PUBLIC_SESSION && state != API.CKS_RW_PUBLIC_SESSION)
            {
                // проверить допустимость состояния
                if (sessionState == state) return RefObject.addRef(session); 
            }
            // получить аутентификацию из кэша
            PasswordCredentials credentials = (PasswordCredentials)
                cache.getData(info(), user, PasswordCredentials.class); 
                
            // проверить наличие аутентификации
            if (credentials != null) 
            {
                // сбросить текущую аутентификацию
                if (sessionState != API.CKS_RO_PUBLIC_SESSION && 
                    sessionState != API.CKS_RW_PUBLIC_SESSION) session.logout();
                
                // при требовании аутентификации администратора
                if (state == API.CKS_RW_SO_FUNCTIONS)
                {
                    // установить аутентификацию
                    session.login(API.CKU_SO, credentials.password()); 
                }
                else {
                    // установить аутентификацию
                    session.login(API.CKU_USER, credentials.password()); 
                }
                // вернуть сеанс
                return RefObject.addRef(session); 
            }
            // проверить допустимость состояния
            if (state == API.CKS_RO_PUBLIC_SESSION || state == API.CKS_RW_PUBLIC_SESSION) 
            {
                // вернуть сеанс
                return RefObject.addRef(session); 
            }
        }
        // заново выполнить аутентификацию 
        authenticate(); 
        
        // создать сеанс
        try (Session session = new Session(module(), slotID, mode, null, null))
        {
            // получить состояние сеанса
            long sessionState = session.getSessionInfo().state(); 
                
            // проверить допустимость состояния
            if (sessionState == state) return RefObject.addRef(session); 
            
            // получить аутентификацию из кэша
            PasswordCredentials credentials = (PasswordCredentials)
                cache.getData(info(), user, PasswordCredentials.class); 
                
            // проверить наличие аутентификации
            if (credentials == null) throw new IllegalStateException(); 
                
            // сбросить текущую аутентификацию
            if (sessionState != API.CKS_RO_PUBLIC_SESSION && 
                sessionState != API.CKS_RW_PUBLIC_SESSION) session.logout();
                
            // при требовании аутентификации администратора
            if (state == API.CKS_RW_SO_FUNCTIONS)
            {
                // установить аутентификацию
                session.login(API.CKU_SO, credentials.password()); 
            }
            else {
                // установить аутентификацию
                session.login(API.CKU_USER, credentials.password()); 
            }
            // вернуть сеанс
            return RefObject.addRef(session); 
        }
	}
	///////////////////////////////////////////////////////////////////////////
	// Управление объектами
	///////////////////////////////////////////////////////////////////////////

	// перечислить контейнеры
	@Override public String[] enumerateObjects()
    {
        // выделить память для списка контейнеров
        List<String> list = new ArrayList<String>(); 
        try {
            // выделить память для атрибутов поиска
            Attribute[] attributes = new Attribute[] { 

                // указать признак нахождения на устройстве
                new Attribute(API.CKA_TOKEN, API.CK_TRUE) 
            }; 
            // открыть сеанс
            try (Session session = openSession(API.CKS_RO_PUBLIC_SESSION)) 
            {
                // для каждого объекта
                for (SessionObject obj : session.findObjects(attributes))
                try {   
					switch ((int)obj.getObjectClass())
					{
					// для сертификата или открытого ключа
					case (int)API.CKO_CERTIFICATE: case (int)API.CKO_PUBLIC_KEY:
					{
                        // определить имя контейнера
                        String name = obj.getLabel();  
                    
                        // добавить имя в список
                        if (!list.contains(name)) list.add(name); break; 
                    }}
                }
                // обработать возможное исключение
                catch (Throwable e) {}                
            }
        }
        // вернуть список имен контейнеров
        catch (Throwable e) {} return list.toArray(new String[list.size()]); 
    }
	// создать контейнер
	@Override public SecurityObject createObject(IRand rand, 
        Object name, Object authenticationData, Object... parameters) throws IOException
    {
        // открыть контейнер
        return openObject(name, "rw"); 
    }
	// открыть контейнер
	@Override public SecurityObject openObject(Object name, String mode) throws IOException
    {
        // указать режим открытия 
        long modePKCS11 = (mode.equals("rw")) ? API.CKF_RW_SESSION : 0; 

        // вернуть объект контейнера
        return new Container(this, name.toString(), modePKCS11); 
    }
	// удалить контейнер
	@Override public void deleteObject(Object name, 
		Authentication[] authentications) throws IOException
    {
        // открыть контейнер
        try (Container container = new Container(
            this, name.toString(), API.CKF_RW_SESSION)) 
        {
            // удалить ключи
            container.deleteKeys(); 
        }
        // вызвать базовую функцию
        super.deleteObject(name, authentications);
    }
	///////////////////////////////////////////////////////////////////////////
	// Алгоритмы устройства
	///////////////////////////////////////////////////////////////////////////

	// получить список алгоритмов
	public final long[] algorithms() 
    { 
        // создать список алгоритмов
        long[] algIDs = new long[this.algIDs.size()]; 
        
        // заполнить список алгоритмов
        for (int i = 0; i < algIDs.length; i++) 
        {
            algIDs[i] = this.algIDs.get(i); 
        }
        return algIDs; 
    }
	// получить информацию об алгоритме
	public final MechanismInfo getAlgorithmInfo(long type) throws IOException
	{
		// получить информацию об алгоритме
		return module().getAlgorithmInfo(slotID, type); 
	}
    // признак поддержки алгоритма
    public final boolean supported(long type, long usage, int keySize)
    {
        // проверить поддержку алгоритма
        if (!algIDs.contains(type)) return false; 
        
        // проверить необходимость последующих проверок
        if (usage == 0 && keySize == 0) return true; 
        try {
            // получить информацию алгоритма
            MechanismInfo info = getAlgorithmInfo(type); 
            
            // проверить способ использования
            if (usage != 0 && (info.flags() & usage) != usage) return false; 
            
            // проверить указание размера 
            if (keySize == 0) return true; 
            
            // проверить поддержку размера ключа
            return (info.minKeySize() <= keySize && keySize <= info.maxKeySize()); 
        }
        // обработать возможную ошибку
        catch (IOException e) { return false; }
    }
	// датчик случайных чисел
	@Override public IRand createRand(Object window) throws IOException
	{
		// получить датчик случайных чисел
		return new Rand(this, provider().generateSeed(this), window); 
	}
	///////////////////////////////////////////////////////////////////////////
	// Объекты устройства
	///////////////////////////////////////////////////////////////////////////

	// найти объекты
	public final byte[][] getKeyIDs(Session session, 
        String label, KeyUsage keyUsage, boolean set) throws IOException
    {
        long KEYX_MASK = KeyUsage.KEY_ENCIPHERMENT  | KeyUsage.KEY_AGREEMENT;          
        long SIGN_MASK = KeyUsage.DIGITAL_SIGNATURE | KeyUsage.CERTIFICATE_SIGNATURE | 
                         KeyUsage.CRL_SIGNATURE     | KeyUsage.NON_REPUDIATION;        
        
        // создать список для найденных объектов
        Map<String, byte[]> keyIDs = new HashMap<String, byte[]>(); 
        Map<String, byte[]> unkIDs = new HashMap<String, byte[]>(); 

        // для каждого найденного объекта
        for (SessionObject obj : session.findTokenObjects(label, new Attribute[0]))
        {
			switch ((int)obj.getObjectClass())
			{
			case (int)API.CKO_CERTIFICATE: 
            {
				// получить идентификатор объекта
				byte[] id = obj.getID(); String strID = Array.toHexString(id);
                
				// назначение сертификата
				KeyUsage certUsage = KeyUsage.NONE;
                try { 
                    // создать объект сертификата
                    Certificate certificate = new Certificate(obj.getValue()); 

					// сохранить назначение сертификата
                    certUsage = certificate.keyUsage(); 
                }
                // обработать возможную ошибку
                catch (Throwable e) {} 
                
                // при отсутствии назначения
                if (certUsage.equals(KeyUsage.NONE))
                {
					// добавить идентификатор в список
					if (!unkIDs.containsKey(strID)) unkIDs.put(strID, id); break; 
                }
                // проверить совпадение атрибутов
                if (set && keyUsage.containsAll(certUsage)) 
                {
					// добавить идентификатор в список
					if (!keyIDs.containsKey(strID)) keyIDs.put(strID, id); 
                }
                // проверить совпадение атрибутов
                else if (!set && certUsage.containsAll(keyUsage)) 
                {
					// добавить идентификатор в список
					if (!keyIDs.containsKey(strID)) keyIDs.put(strID, id); 
                }
                break; 
            }
			case (int)API.CKO_PUBLIC_KEY: 
			{
				// получить идентификатор объекта
				byte[] id = obj.getID(); String strID = Array.toHexString(id);

                // указать значения атрибутов по умолчанию
                Attribute[] attributesUsage = new Attribute[] { 
                    new Attribute(API.CKA_VERIFY, Byte.class), 
                    new Attribute(API.CKA_WRAP  , Byte.class)
                };                 
                // получить атрибуты использования
                attributesUsage = obj.getSafeAttributes(attributesUsage);
                
                // при отсутствии атрибутов
                if (attributesUsage[0].value() == null && attributesUsage[1].value() == null)
                {
					// добавить идентификатор в список
					if (!unkIDs.containsKey(strID)) unkIDs.put(strID, id); break; 
                }
                // указать значения атрибутов по умолчанию
                KeyUsage decodedUsage = KeyUsage.NONE; 
                
                // при использовании при проверке подписи
                if ((Byte)attributesUsage[0].value() != null && 
                    (Byte)attributesUsage[0].value() != API.CK_FALSE)
                {
                    // указать допустимость подписи
                    decodedUsage = new KeyUsage(decodedUsage.value() | SIGN_MASK); 
                }
                // при использовании при шифровании
                if ((Byte)attributesUsage[1].value() != null && 
                    (Byte)attributesUsage[1].value() != API.CK_FALSE)
                {
                    // указать допустимость обмена
                    decodedUsage = new KeyUsage(decodedUsage.value() | KEYX_MASK); 
                }
                // проверить совпадение атрибутов
                if (set && keyUsage.containsAll(decodedUsage)) 
                {
                    // добавить идентификатор в список
                    if (!keyIDs.containsKey(strID)) keyIDs.put(strID, id);  
                }
                // проверить совпадение атрибутов
                else if (!set && decodedUsage.containsAll(keyUsage)) 
                {
                    // добавить идентификатор в список
                    if (!keyIDs.containsKey(strID)) keyIDs.put(strID, id);  
                }
                break; 
            }}
        }
		// переключиться на объекты с неизвестным назначением
		if (keyIDs.isEmpty() && !set) keyIDs = unkIDs;
        
		// вернуть найденные объекты
		return keyIDs.values().toArray(new byte[keyIDs.size()][]); 
    }
	// найти объекты
	public final byte[][] getKeyIDs(Session session, String label) throws IOException
    {
        // создать список для найденных объектов
		Map<String, byte[]> keyIDs = new HashMap<String, byte[]>();

		// для каждого найденного объекта
		for (SessionObject obj : session.findTokenObjects(label, new Attribute[0]))
		{
			switch ((int)obj.getObjectClass())
			{
			case (int)API.CKO_CERTIFICATE: case (int)API.CKO_PUBLIC_KEY:
			{
				// получить идентификатор объекта
				byte[] id = obj.getID(); String strID = Array.toHexString(id);

				// добавить идентификатор в список
				if (!keyIDs.containsKey(strID)) keyIDs.put(strID, id); break; 
			}}
		}
		// вернуть найденные объекты
		return keyIDs.values().toArray(new byte[keyIDs.size()][]); 
	}
	// найти объекты
	public final Certificate[] enumerateAllCertificates(Session session, String label) throws IOException
    {
        // указать фильтр поиска
        Attribute[] attributes = new Attribute[] { 
            new Attribute(API.CKA_CLASS, API.CKO_CERTIFICATE) 
        }; 
        // создать список сертификатов
        List<Certificate> certificates = new ArrayList<Certificate>(); 
        
		// для каждого найденного объекта
		for (SessionObject obj : session.findTokenObjects(label, attributes))		
        try { 
            // добавить сертификат в список
            certificates.add(new Certificate(obj.getValue())); 
        }
        // вернуть список сертификатов
        catch (Throwable e) {} return certificates.toArray(new Certificate[certificates.size()]); 
    }
    ///////////////////////////////////////////////////////////////////////
    // Подготовится к генерации/записи ключевой пары
    ///////////////////////////////////////////////////////////////////////
    public byte[] prepareKeyPair(Session session, String label, 
        byte[] keyID, IRand rand, KeyUsage keyUsage) throws IOException
    {
        if (keyID != null)
        {
            // выделить память для атрибутов поиска
            Attribute[] attributes = new Attribute[] { new Attribute(API.CKA_ID, keyID) }; 

            // перечислить объекты контейнера
            SessionObject[] objects = session.findTokenObjects(label, attributes);

            // удалить объекты контейнера
            for (SessionObject obj : objects) session.destroyObject(obj);
        }
        else {
            // найти объекты для удаления
            byte[][] keyIDs = getKeyIDs(session, label, keyUsage, true);

            // при наличии объектов для удаления
            for (int i = 0; i < keyIDs.length; i++) 
            { 
                // выделить память для атрибутов поиска
                Attribute[] attributes = new Attribute[] { new Attribute(API.CKA_ID, keyIDs[i]) }; 

                // перечислить объекты контейнера
                SessionObject[] objects = session.findTokenObjects(label, attributes);

                // удалить объекты контейнера
                for (SessionObject obj : objects) session.destroyObject(obj);
            }
            // указать идентификатор ключа
            if (keyIDs.length > 0) keyID = keyIDs[0];
        }
        // при отсутствии идентификатора
        if (keyID == null) { keyID = new byte[8]; 
                
            // сгенерировать идентификатор
            rand.generate(keyID, 0, keyID.length);

            // выделить память для атрибутов поиска
	        Attribute[] attributes = new Attribute[] { new Attribute(API.CKA_ID, keyID) }; 

            // перечислить объекты контейнера
	        while (session.findTokenObjects(label, attributes).length != 0)
            {
	            // сгенерировать идентификатор
                rand.generate(keyID, 0, keyID.length);
	        }
        }
        return keyID; 
    }
}
