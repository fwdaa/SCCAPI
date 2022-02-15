package aladdin.capi;
import aladdin.*; 
import java.io.*; 
import java.util.*; 

///////////////////////////////////////////////////////////////////////
// Выбор аутентификации
///////////////////////////////////////////////////////////////////////
public class AuthenticationSelector
{
    // конструктор
    public AuthenticationSelector(String user) 
        
        // сохранить переданные параметры
        { this.user = user; } private final String user; 

    // тип пользователя
    public final String user() { return user; } 

    ///////////////////////////////////////////////////////////////////////
    // Получить список аутентификаций
    ///////////////////////////////////////////////////////////////////////
    public Authentication[] getAuthentications(SecurityObject obj)
    {
        // создать список типов возможных аутентификаций
        List<Class<? extends Credentials>> authenticationTypes = 
            new ArrayList<Class<? extends Credentials>>(); 
        
        // для всех допустимых аутентификаций
        for (Class<? extends Credentials> authenticationType : obj.getAuthenticationTypes(user))
        {
            // получить сервис аутентификации
            AuthenticationService service = obj.getAuthenticationService(user, authenticationType);
            
            // проверить установку аутентификации
            if (service.canLogin()) authenticationTypes.add(authenticationType); 
        }
        // получить возможные аутентификации
        return getAuthentications(obj, authenticationTypes); 
    }
    // получить требуемую аутентификацию
    protected Authentication[] getAuthentications(SecurityObject obj, 
        List<Class<? extends Credentials>> authenticationTypes) 
    { 
        // аутентификации отсутствуют
        return new Authentication[0]; 
    } 
    ///////////////////////////////////////////////////////////////////////
    // Создать объект
    ///////////////////////////////////////////////////////////////////////
    public SecurityObject createObject(IProvider provider, Scope scope, 
        IRand rand, String name, Object authenticationData, Object... parameters) throws IOException
    {
        // проверить корректность параметра
        if (scope == Scope.ANY) throw new IllegalArgumentException(); 

        // удалить последний разделитель
        if (name.endsWith(File.separator)) name = name.substring(0, name.length() - 1); 
        
        // для всех хранилищ верхнего уровня
        for (String storeName : provider.enumerateStores(scope))
        {
            // при совпадении имени 
            if (name.compareToIgnoreCase(storeName) == 0) 
            {
                // открыть хранилище
                try (SecurityStore store = provider.openStore(scope, storeName))
                {  
                    // указать тип аутентификации
                    store.setAuthentications(getAuthentications(store)); 
                    
                    // вернуть хранилище
                    return RefObject.addRef(store); 
                }
            }
            // проверить наличие имени в пути
            else if (name.toLowerCase().startsWith(storeName.toLowerCase() + File.separator))
            { 
                // удалить начальную часть
                name = name.substring(storeName.length() + 1); 

                // открыть хранилище
                try (SecurityStore store = provider.openStore(scope, storeName))
                {
                    // указать тип аутентификации
                    store.setAuthentications(getAuthentications(store));

                    // создать объект
                    return createObject(store, rand, name, authenticationData, parameters); 
                }
            }
        }
        // при ошибке выбросить исключение
        throw new NoSuchElementException(); 
    }
    public SecurityObject createObject(SecurityStore store, IRand rand, String name, 
        Object authenticationData, Object... parameters) throws IOException
    {
        // выполнить разбор имени
        String[] path = store.parseObjectName(name); if (path.length == 1)
        {
            // указать генератор случайных данных
            try (IRand rebindRand = rebindRand(rand))
            { 
                // создать объект
                return store.createObject(rebindRand, path[0], authenticationData, parameters);
            }
        }
        // открыть хранилище
        else try (SecurityObject obj = store.openObject(path[0], "rw"))
        { 
            // проверить тип объекта
            if (!(obj instanceof SecurityStore)) throw new NoSuchElementException(); 

            // указать тип аутентификации
            obj.setAuthentications(getAuthentications(obj));

            // создать объект 
            return createObject(((SecurityStore)obj), rand, path[1], authenticationData, parameters); 
        }
    }
    ///////////////////////////////////////////////////////////////////////
    // Открыть объект
    ///////////////////////////////////////////////////////////////////////
    public SecurityObject openObject(IProvider provider, 
        Scope scope, String name, String access) throws IOException
    {
        // проверить корректность параметра
        if (scope == Scope.ANY) throw new IllegalArgumentException(); 

        // удалить последний разделитель
        if (name.endsWith(File.separator)) name = name.substring(0, name.length() - 1); 
        
        // для всех хранилищ верхнего уровня
        for (String storeName : provider.enumerateStores(scope))
        {
            // при совпадении имени 
            if (name.compareToIgnoreCase(storeName) == 0) 
            {
                // открыть хранилище
                try (SecurityStore store = provider.openStore(scope, storeName))
                {  
                    // указать тип аутентификации
                    store.setAuthentications(getAuthentications(store)); 
                    
                    // вернуть хранилище
                    return RefObject.addRef(store); 
                }
            }
            // проверить наличие имени в пути
            else if (name.toLowerCase().startsWith(storeName.toLowerCase() + File.separator))
            { 
                // удалить начальную часть
                name = name.substring(storeName.length() + 1); 

                // открыть хранилище
                try (SecurityStore store = provider.openStore(scope, storeName))
                {
                    // указать тип аутентификации
                    store.setAuthentications(getAuthentications(store)); 

                    // открыть объект
                    return openObject(store, name, access); 
                }
            }
        }
        // при ошибке выбросить исключение
        throw new NoSuchElementException(); 
    }
    public SecurityObject openObject(SecurityStore store, String name, String access) throws IOException
    {
        // выполнить разбор имени
        String[] path = store.parseObjectName(name); if (path.length == 1)
        {
            // открыть объект
            try (SecurityObject obj = store.openObject(path[0], access))
            {
                // указать тип аутентификации
                obj.setAuthentications(getAuthentications(obj));
                
                // вернуть объект
                return RefObject.addRef(obj); 
            }
        }
        // открыть хранилище
        else try (SecurityObject obj = store.openObject(path[0], access))
        { 
            // проверить тип объекта
            if (!(obj instanceof SecurityStore)) throw new NoSuchElementException(); 

            // указать тип аутентификации
            obj.setAuthentications(getAuthentications(obj));

            // открыть объект 
            return openObject(((SecurityStore)obj), path[1], access); 
        }
    }
    ///////////////////////////////////////////////////////////////////////
    // Удалить объект
    ///////////////////////////////////////////////////////////////////////
    public void deleteObject(IProvider provider, Scope scope, String name) throws IOException
    {
        // проверить корректность параметра
        if (scope == Scope.ANY) throw new IllegalArgumentException(); 

        // удалить последний разделитель
        if (name.endsWith(File.separator)) name = name.substring(0, name.length() - 1); 
        
        // для всех хранилищ верхнего уровня
        for (String storeName : provider.enumerateStores(scope))
        {
            // хранилище верхнего уровня не удаляется
            if (name.compareToIgnoreCase(storeName) == 0) throw new IllegalStateException();
            
            // проверить наличие имени в пути
            if (name.toLowerCase().startsWith(storeName.toLowerCase() + File.separator))
            { 
                // удалить начальную часть
                name = name.substring(storeName.length() + 1); 

                // открыть хранилище
                try (SecurityStore store = provider.openStore(scope, storeName))
                {
                    // указать тип аутентификации
                    store.setAuthentications(getAuthentications(store)); 

                    // удалить объект
                    deleteObject(store, name); return; 
                }
            }
        }
        // при ошибке выбросить исключение
        throw new NoSuchElementException(); 
    }
    public void deleteObject(SecurityStore store, String name) throws IOException
    {
        // выполнить разбор имени
        String[] path = store.parseObjectName(name); if (path.length == 1)
        {
            // список аутентификаций
            Authentication[] authentications = new Authentication[0]; 

            // открыть объект
            try (SecurityObject obj = store.openObject(path[0], "r"))
            {
                // получить возможные аутентификации
                authentications = getAuthentications(obj); 
            }
            // обработать возможное исключение
            catch (NoSuchElementException e) { return; }
            
            // удалить объект
            store.deleteObject(path[0], authentications); 
        }
        // открыть хранилище
        else try (SecurityObject obj = store.openObject(path[0], "rw"))
        {
            // проверить тип объекта
            if (!(obj instanceof SecurityStore)) throw new NoSuchElementException(); 

            // указать тип аутентификации
            obj.setAuthentications(getAuthentications(obj));

            // удалить объект 
            deleteObject(((SecurityStore)obj), path[1]); 
        }
    }
    ///////////////////////////////////////////////////////////////////////
    // Сгенерировать пару ключей
	///////////////////////////////////////////////////////////////////////
    public ContainerKeyPair generateKeyPair(CryptoProvider provider, 
        SecurityInfo info, IRand rand, IParametersFactory factory, 
        String keyOID, KeyUsage keyUsage, KeyFlags keyFlags) throws IOException
	{
        // указать существующий контейнер
        try (ClientContainer clientContainer = new ClientContainer(provider, info, this))
        {
            // сгенерировать пару ключей
            return clientContainer.generateKeyPair(rand, factory, keyOID, keyUsage, keyFlags); 
        }
        // при отсутствии контейнера
        catch (Throwable e) { Container container = null; 
        
            // открыть хранилище
            try (SecurityStore store = (SecurityStore)openObject(provider, info.scope, info.store, "rw"))
            { 
                // получить типы аутентификации дочерних объектов
                List<Class<? extends Authentication>> authenticationTypes = 
                    new ArrayList<Class<? extends Authentication>>(
                        store.getChildAuthenticationTypes(user)
                ); 
                // указать генератор случайных данных
                try (IRand rebindRand = rebindRand(rand))
                {
                    // при необходимости аутентификации
                    if (!authenticationTypes.isEmpty() && !authenticationTypes.contains(null))
                    {
                        // отобразить диалог создания контейнера
                        container = (Container)showCreate(provider, info, rebindRand, authenticationTypes, keyOID); 
                    }
                    // создать объект без аутентификации
                    else container = (Container)store.createObject(rand, info.name, null, keyOID); 
                    try { 
                        // выбрать параметры алгоритма
                        IParameters keyParameters = factory.getParameters(rand, keyOID, keyUsage); 

                        // сгенерировать ключи в контейнере
                        try (KeyPair keyPair = container.generateKeyPair(
                            rand, null, keyOID, keyParameters, keyUsage, keyFlags)) 
                        { 
                            // закрыть контейнер
                            return new ContainerKeyPair(info, keyPair.keyID, keyOID, null);
                        }
                    }
                    // освободить выделенные ресурсы
                    finally { RefObject.release(container); }
                }
            }
        }
    }
    ///////////////////////////////////////////////////////////////////////
	// Импортировать пару ключей
	///////////////////////////////////////////////////////////////////////
	public ContainerKeyPair exportKeyPair(
        CryptoProvider providerFrom, SecurityInfo infoFrom, byte[] keyID, 
        CryptoProvider providerTo, SecurityInfo infoTo, IRand rand, 
        KeyUsage keyUsage, KeyFlags keyFlags) throws IOException
	{
        // открыть контейнер
        try (Container containerFrom = (Container)openObject(
            providerFrom, infoFrom.scope, infoFrom.fullName(), "r"))
        {
            // получить открытый ключ
            IPublicKey publicKey = containerFrom.getPublicKey(keyID);

            // проверить наличие ключа
            if (publicKey == null) throw new NoSuchElementException();

            // получить сертификат
            Certificate certificate = containerFrom.getCertificate(keyID);
                    
            // получить личный ключ
            try (IPrivateKey privateKey = containerFrom.getPrivateKey(keyID))
            {
                // указать существующий контейнер
                try (ClientContainer clientContainerTo = new ClientContainer(providerTo, infoTo, this))
                {
                    // импортировать пару ключей
                    return clientContainerTo.importKeyPair(rand, publicKey, privateKey, certificate, keyUsage, keyFlags); 
                }
                // при отсутствии контейнера
                catch (Throwable e) { Container containerTo = null; 

                    // открыть хранилище
                    try (SecurityStore storeTo = (SecurityStore)openObject(providerTo, infoTo.scope, infoTo.store, "rw"))
                    { 
                        // получить типы аутентификации дочерних объектов
                        List<Class<? extends Authentication>> authenticationTypes = 
                            new ArrayList<Class<? extends Authentication>>(
                                storeTo.getChildAuthenticationTypes(user)
                        ); 
                        // указать генератор случайных данных
                        try (IRand rebindRand = rebindRand(rand))
                        {
                            // при наличии аутентификации
                            if (!authenticationTypes.isEmpty() && !authenticationTypes.contains(null))
                            {
                                // отобразить диалог создания контейнера
                                containerTo = (Container)showCreate(providerTo, infoTo, rebindRand, authenticationTypes, publicKey.keyOID()); 
                            }
                            // создать объект без аутентификации
                            else containerTo = (Container)storeTo.createObject(rand, infoTo.name, null, publicKey.keyOID()); 
                            try { 
  		                        // импортировать ключи в контейнер
			                    try (KeyPair keyPair = containerTo.importKeyPair(rand, publicKey, privateKey, keyUsage, keyFlags)) 
                                { 
                                    // записать сертификат в контейнер
                                    if (certificate != null) containerTo.setCertificate(keyPair.keyID, certificate);
                                            
                                    // вернуть описание пары ключей контейнера
                                    return new ContainerKeyPair(infoTo, keyPair.keyID, publicKey.keyOID(), certificate); 
                                }
                            }
                            // освободить выделенные ресурсы
                            finally { RefObject.release(containerTo); }
                        }
                    }
                }
            }
        }
    }
    ///////////////////////////////////////////////////////////////////////
	// Открыть или создать контейнер 
	///////////////////////////////////////////////////////////////////////
    public Container openOrCreate(CryptoProvider provider, 
        SecurityInfo info, Object... parameters) throws IOException
    {
        // открыть хранилище
        try (SecurityStore store = (SecurityStore)openObject(
            provider, info.scope, info.store, "rw"))
        { 
            // открыть контейнер
            try (SecurityObject container = store.openObject(info.name, "rw"))
            { 
                // указать способ аутентификации
                container.setAuthentications(getAuthentications(container)); 
                    
                // вернуть контейнер
                return (Container)RefObject.addRef(container); 
            }
            // при возникновении ошибки
            catch (NoSuchElementException e) 
            { 
                // получить типы аутентификации дочерних объектов
                List<Class<? extends Authentication>> authenticationTypes = 
                    new ArrayList<Class<? extends Authentication>>(
                        store.getChildAuthenticationTypes(user)
                ); 
                // создать генератор случайных данных
                try (IRand rand = createRand(provider, store))
                { 
                    // при наличии аутентификации
                    if (!authenticationTypes.isEmpty() && !authenticationTypes.contains(null))
                    {
                        // отобразить диалог создания контейнера
                        return (Container)showCreate(provider, info, rand, authenticationTypes, parameters);
                    }
                    // создать объект без аутентификации
                    else return (Container)store.createObject(rand, info.name, null, parameters); 
                }
            }
        }
    }
    public SecurityObject showCreate(CryptoProvider provider, SecurityInfo info, IRand rand, 
        List<Class<? extends Authentication>> authenticationTypes, Object... parameters) { return null; }

    ///////////////////////////////////////////////////////////////////////
    // Генератор случайных данных
	///////////////////////////////////////////////////////////////////////
    public IRand createRand(CryptoProvider provider, SecurityObject container) throws IOException
    {
        // создать генератор случайных данных
        return provider.createRand(container, null); 
    }
    // указать другое графическое окружение
    public IRand rebindRand(IRand rand) { return RefObject.addRef(rand); }
}
