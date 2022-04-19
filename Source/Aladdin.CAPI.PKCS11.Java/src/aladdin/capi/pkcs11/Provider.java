package aladdin.capi.pkcs11;
import aladdin.*; 
import aladdin.capi.*; 
import aladdin.pkcs11.*; 
import java.io.*;
import java.util.*;

///////////////////////////////////////////////////////////////////////////
// Криптографический провайдер
///////////////////////////////////////////////////////////////////////////
public abstract class Provider extends aladdin.capi.CryptoProvider
{
    // конструктор
    public Provider(String name) { this.name = name; } 
    
    // имя провайдера
	@Override public final String name() { return name; } private final String name; 
    
	// интерфейс вызова функций
	public abstract Module module();  
    
    // возможность импорта ключевой пары в память
    public boolean canImportSessionPair(Applet applet) { return true; }

	///////////////////////////////////////////////////////////////////////
	// Управление устройствами
	///////////////////////////////////////////////////////////////////////
    @Override
	public String[] enumerateStores(Scope scope)
	{ 
        // проверить область видимости
        if (scope != Scope.SYSTEM) return new String[0]; 

        // выделить память для имен смарт-карт
        List<String> stores = new ArrayList<String>(); 
        try { 
            // получить список считывателей
            long[] slotList = module().getSlotList(true); 

            // для всех найденных смарт-карт
            for (int i = 0; i < slotList.length; i++) 
            {
                // создать объект считывателя
                try (Slot slot = new Slot(this, slotList[i])) 
                {
                    // проверить наличие смарт-карты
                    if (slot.getState() != aladdin.pcsc.ReaderState.CARD) continue; 
                    
                    // добавить смарт-карту в список
                    if (!stores.contains(slot.name())) stores.add(slot.name()); 
                }
                // обработать возможную ошибку
                catch (Throwable e) {} 
            }
        }
        // вернуть список смарт-карт
        catch (Throwable e) {} return stores.toArray(new String[stores.size()]); 
    } 
	@Override
	public final SecurityStore openStore(Scope scope, String storeName) throws IOException 
    { 
        // проверить область видимости
        if (scope != Scope.SYSTEM) throw new NoSuchElementException(); 

        // получить список считывателей
        long[] slotList = module().getSlotList(true); 

        // для всех найденных смарт-карт
        for (int i = 0; i < slotList.length; i++) 
        {
            // получить имя считывателя
            SlotInfo info = module().getSlotInfo(slotList[i]); 

            // проверить совпадение имен
            if (!info.slotDescription().equals(storeName)) continue; 
            
            // открыть объект смарт-карты
            return new Token(this, slotList[i]); 
        }
        // при ошибке выбросить исключение
        throw new NoSuchElementException(); 
    }
    // фабрика генераторов случайных данных
	@Override public IRandFactory createRandFactory(SecurityObject scope, boolean strong)
    {
	    // проверить область видимости
	    if (scope instanceof Container) return RefObject.addRef(((Container)scope).store());
	        
	    // проверить область видимости
	    if (scope instanceof Applet) return RefObject.addRef((Applet)scope); 
        
        // вернуть фабрика генераторов
        return RefObject.addRef(this);
    }
    // создать генератор случайных данных
    @Override public IRand createRand(Object window) throws IOException
    { 
        // получить список считывателей
        long[] slotList = module().getSlotList(true); 
	
        // для каждого считывателя
        for (int i = 0; i < slotList.length; i++)
        try {
            // получить информацию устройства
            SlotInfo slotInfo = module().getSlotInfo(slotList[i]); 
            
            // проверить наличие смарт-карты
            if ((slotInfo.flags() & API.CKF_TOKEN_PRESENT) == 0) continue;
            
            // получить информацию апплета
            TokenInfo tokenInfo = module().getTokenInfo(slotList[i]); 

            // проверить наличие генератора случайных данных
            if ((tokenInfo.flags() & API.CKF_RNG) == 0) continue; 
            
            // создать объект смарт-карты
            try (Token token = new Token(this, slotList[i]))
            {
                // создать объект апплета
                try (Applet applet = new Applet(token, slotList[i])) 
                { 
                    // вернуть генератор случайных данных
                    return applet.createRand(window); 
                }
            }
        }
        // вызвать базовую функцию
        catch (Throwable e) {} return super.createRand(window);
	}
	// найти устройство с реализацией алгоритма
	public final Applet findApplet(SecurityObject scope, 
        long algID, long usage, int keySize) throws IOException
	{
        // проверить область видимости
        if (scope instanceof Container) 
        {
            // получить апплет контейнера
            Applet applet = ((Container)scope).store(); 
            
            // проверить поддержку алгоритма
            if (!applet.supported(algID, usage, keySize)) return null; 
            
            // вернуть устройство для контейнера
	        return RefObject.addRef(applet);
        }
        // проверить область видимости
        if (scope instanceof Applet) { Applet applet = (Applet)scope;
        
            // проверить поддержку алгоритма
            if (!applet.supported(algID, usage, keySize)) return null; 
            
            // вернуть устройство 
	        return RefObject.addRef(applet);
        }
        // получить список считывателей
        long[] slotList = module().getSlotList(true); 

        // для каждого считывателя
        for (int i = 0; i < slotList.length; i++)
        try {
            // получить информацию устройства
            SlotInfo slotInfo = module().getSlotInfo(slotList[i]); 
            
            // проверить наличие смарт-карты
            if ((slotInfo.flags() & API.CKF_TOKEN_PRESENT) == 0) continue;
            
            // создать объект смарт-карты
            try (Token token = new Token(this, slotList[i]))
            {
                // создать объект апплета
                try (Applet applet = new Applet(token, slotList[i]))
                {
                    // проверить поддержку алгоритма
                    if (!applet.supported(algID, usage, keySize)) continue; 
                        
                    // вернуть найденный апплет
                    return RefObject.addRef(applet);
                }
            }
        }
        catch (Throwable e) {} return null;
    }
	///////////////////////////////////////////////////////////////////////
	// Особенности провайдера
	///////////////////////////////////////////////////////////////////////
	public byte[] generateSeed(Applet applet) throws IOException { return null; } 
	
	// преобразование типа ключей
	public SecretKey convertSecretKey(
        SessionObject object, SecretKeyFactory keyFactory) throws IOException
    {
        // получить атрибуты ключа
	    Attributes attributes = getKeyAttributes(object, 
            new Attribute(API.CKA_KEY_TYPE, API.CKK_GENERIC_SECRET)
        ); 
        // при возможности извлечения значения
        if ((Byte)attributes.get(API.CKA_EXTRACTABLE).value() != API.CK_FALSE && 
            (Byte)attributes.get(API.CKA_SENSITIVE  ).value() == API.CK_FALSE)
        {
            // получить значение ключа
            Attribute attribute = new Attribute(API.CKA_VALUE, object.getValue()); 
            
            // добавить атрибут в список
            attributes = attributes.join(new Attributes(attribute)); 
        }
        // при отсутствии на смарт-карте
        if ((Byte)attributes.get(API.CKA_TOKEN).value() == API.CK_FALSE)
        {
            // проверить наличие значения
            if (attributes.get(API.CKA_VALUE) == null)
            {
                // при ошибке выбросить исключение
                throw new aladdin.pkcs11.Exception(API.CKR_KEY_UNEXTRACTABLE); 
            }
            // создать ключ по сеансовому объекту
            return new SecretKey(null, keyFactory, attributes); 
        }
        else {
            // определить идентификатор слота
            long slotID = object.session().slotID(); 
            
            // создать объект смарт-карты
            try (Token token = new Token(this, slotID))
            {
                // указать апплет
                try (Applet applet = new Applet(token, slotID)) 
                {
                    // создать ключ по сеансовому объекту
                    return new SecretKey(applet, keyFactory, attributes); 
                }
            }
        }
    }
    // преобразовать тип открытого ключа
	public abstract IPublicKey convertPublicKey(
        Applet applet, SessionObject object) throws IOException;
    
    // преобразовать тип личного ключа
	public abstract PrivateKey convertPrivateKey(SecurityObject scope, 
        SessionObject object, IPublicKey publicKey) throws IOException;
    
	// преобразование типа ключей
	public final SessionObject toSessionObject(
        Session session, ISecretKey key, Attribute[] keyAttributes) throws IOException
    {
        // проверить тип ключа
        if (key instanceof SecretKey) return ((SecretKey)key).toSessionObject(session, keyAttributes); 
        
        // получить значение ключа
        if (key.value() == null) throw new aladdin.pkcs11.Exception(API.CKR_KEY_UNEXTRACTABLE); 
        
        // создать список атрибутов
        Attribute[] attributes = new Attribute[] {

            // указать тип ключа
            new Attribute(API.CKA_CLASS, API.CKO_SECRET_KEY), 

            // указать тип ключа
            new Attribute(API.CKA_KEY_TYPE, API.CKK_GENERIC_SECRET), 

            // указать извлекаемость значения
            new Attribute(API.CKA_EXTRACTABLE, API.CK_TRUE ), 
            new Attribute(API.CKA_SENSITIVE  , API.CK_FALSE), 

            // указать значение ключа
            new Attribute(API.CKA_VALUE, key.value()) 
        }; 
        // добавить атрибуты ключа
        attributes = Attribute.join(attributes, keyAttributes); 
        
        // создать сеансовый объект
        return session.createObject(attributes, null); 
    }
	public final SessionObject toSessionObject(Session session, 
        IPublicKey publicKey, MechanismInfo info, Attribute[] keyAttributes) throws IOException
    {
        // получить атрибуты открытого ключа
        Attribute[] publicKeyAttributes = publicKeyAttributes(null, publicKey, info); 

        // проверить поддержку ключа
        if (publicKeyAttributes == null) throw new UnsupportedOperationException(); 

        // указать тип ключа
        Attribute[] attributes = new Attribute[] {
            new Attribute(API.CKA_CLASS, API.CKO_PUBLIC_KEY)
        }; 
        // добавить атрибуты открытого ключа
        attributes = Attribute.join(attributes, publicKeyAttributes); 
        
        // добавить атрибуты открытого ключа
        attributes = Attribute.join(attributes, keyAttributes); 
        
        // создать сеансовый объект
        return session.createObject(attributes, null); 
    }
	public final SessionObject toSessionObject(Session session, 
        IPrivateKey privateKey, MechanismInfo info, Attribute[] keyAttributes) throws IOException
    {
        // проверить тип ключа
        if (privateKey instanceof PrivateKey)
        {
            // создать сеансовый объект
            return ((PrivateKey)privateKey).toSessionObject(session, keyAttributes); 
        }
        // получить атрибуты личного ключа
        Attribute[] privateKeyAttributes = privateKeyAttributes(null, privateKey, info); 

        // проверить поддержку ключа
        if (privateKeyAttributes == null) throw new UnsupportedOperationException(); 

        // указать тип ключа
        Attribute[] attributes = new Attribute[] {
            new Attribute(API.CKA_CLASS, API.CKO_PRIVATE_KEY)
        }; 
        // добавить атрибуты личного ключа
        attributes = Attribute.join(attributes, privateKeyAttributes); 
        
        // добавить атрибуты личного ключа
        attributes = Attribute.join(attributes, keyAttributes); 
        
        // создать сеансовый объект
        return session.createObject(attributes, null); 
    }
	// атрибуты открытого и личного ключа
	public abstract Attribute[] publicKeyAttributes(
        Applet applet, IPublicKey  publicKey,  MechanismInfo info) throws IOException;  
	public abstract Attribute[] privateKeyAttributes(
        Applet applet, IPrivateKey privateKey, MechanismInfo info) throws IOException; 
    
	// атрибуты симметричного ключа
	public Attribute[] secretKeyAttributes(
        SecretKeyFactory keyFactory, int keySize, boolean hasValue) 
    { 
        // атрибуты созданного ключа
        if (hasValue) return new Attribute[] {
            new Attribute(API.CKA_KEY_TYPE , API.CKK_GENERIC_SECRET) 
        }; 
        // атрибуты создаваемого ключа
        return new Attribute[] {
            new Attribute(API.CKA_KEY_TYPE , API.CKK_GENERIC_SECRET), 
            new Attribute(API.CKA_VALUE_LEN, keySize               ) 
        }; 
    }
    // получить атрибуты ключа
    public Attributes getKeyAttributes(SessionObject object, Attribute... attributes) throws IOException
    {
        if (object.onToken())
        {
            // выделить память для атрибутов
            Attribute[] keyAttributes = new Attribute[] { 

                // задать стандартные типы атрибутов
                new Attribute(API.CKA_TOKEN      , API.CK_TRUE ), 
                new Attribute(API.CKA_EXTRACTABLE, API.CK_TRUE ),  
                new Attribute(API.CKA_SENSITIVE  , API.CK_FALSE),  

                // задать стандартные типы атрибутов
                new Attribute(API.CKA_CLASS   , Long  .class), 
                new Attribute(API.CKA_KEY_TYPE, Long  .class), 
                new Attribute(API.CKA_ID      , byte[].class)
            }; 
            // указать дополнительные атрибуты
            attributes = Attribute.join(keyAttributes, attributes);
        }
        else {
            // выделить память для атрибутов
            Attribute[] keyAttributes = new Attribute[] { 

                // задать стандартные типы атрибутов
                new Attribute(API.CKA_TOKEN      , API.CK_FALSE), 
                new Attribute(API.CKA_EXTRACTABLE, API.CK_TRUE ),  
                new Attribute(API.CKA_SENSITIVE  , API.CK_FALSE),  

                // задать стандартные типы атрибутов
                new Attribute(API.CKA_CLASS   , Long  .class), 
                new Attribute(API.CKA_KEY_TYPE, Long  .class), 
            }; 
            // указать дополнительные атрибуты
            attributes = Attribute.join(keyAttributes, attributes);
        }
        // получить атрибуты объекта
	    return new Attributes(object.getAttributes(attributes)); 
    }
} 
