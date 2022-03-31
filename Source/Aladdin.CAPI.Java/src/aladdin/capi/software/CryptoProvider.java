package aladdin.capi.software;
import aladdin.OS;
import aladdin.*;
import aladdin.io.*;
import aladdin.capi.*;
import aladdin.asn1.iso.*; 
import java.io.*; 
import java.lang.reflect.*;
import java.util.*; 

///////////////////////////////////////////////////////////////////////////
// Провайдер программных алгоритмов
///////////////////////////////////////////////////////////////////////////
public abstract class CryptoProvider extends aladdin.capi.CryptoProvider
{
    // фабрика алгоритмов и фабрика генераторов
    private final Factories factories; private final IRandFactory randFactory; 
    
    // тип контейнеров и расширения файлов
    private final String type; private final String[] extensions; 
    
	// конструктор
	public CryptoProvider(Iterable<Factory> factories, 
        IRandFactory randFactory, String type, String[] extensions) 
	{ 
		// сохранить фабрики алгоритмов
		this.factories = new Factories(true, factories); 
        
        // сохранить фабрику генераторов
        this.randFactory = RefObject.addRef(randFactory); 

        // сохранить тип контейнеров и расширения файлов
        this.type = type; this.extensions = extensions;
	} 
    // освободить ресурсы
    @Override protected void onClose() throws IOException
    { 
        // освободить ресурсы
        RefObject.release(randFactory); factories.close(); super.onClose(); 
    }
    // имя провайдера
    @Override public String name() 
    { 
        // имя провайдера
        return String.format("%1$s Cryptographic Provider", type); 
    }
    // фабрика алгоритмов
    public final Factory factory() { return factories; }

    // используемые расширения
    public final String[] extensions() { return extensions; } 
    
    ///////////////////////////////////////////////////////////////////////
    // Генерация случайных данных
    ///////////////////////////////////////////////////////////////////////
    
    // создать генератор случайных данных
    @Override public IRand createRand(Object window) throws IOException 
    { 
        // создать генератор случайных данных
        return randFactory.createRand(window); 
    } 
	///////////////////////////////////////////////////////////////////////
	// управление контейнерами провайдера
	///////////////////////////////////////////////////////////////////////
	@Override public String[] enumerateStores(Scope scope)
	{
        // проверить корректность параметра
        if (!scope.equals(Scope.SYSTEM) && !scope.equals(Scope.USER)) 
        {
            // при ошибке выбросить исключение
            throw new IllegalArgumentException(); 
        }
        // создать список хранилищ
        List<String> stores = new ArrayList<String>(); 
        
        // добавить файловое хранилище
        if (isSupportConfig(scope)) { stores.add("FILE"); 

            // добавить файл конфигурации
            if (scope.equals(Scope.SYSTEM)) stores.add("FSLM"); 
            if (scope.equals(Scope.USER  )) stores.add("FSCU"); 
        }
        // добавить хранилище в памяти
        stores.add("MEMORY"); return stores.toArray(new String[stores.size()]); 
	}
	// определить хранилище контейнеров
	@Override public SecurityStore openStore(Scope scope, String storeName) 
    { 
        // преобразовать имя в верхний регистр
        storeName = storeName.toUpperCase(); 
        
        // вернуть хранилище в памяти
        if (storeName.equals("MEMORY")) return new MemoryStore(this);
        
        // для файлового хранилища
        else if (storeName.equals("FILE"))
        { 
            // проверить поддержку XML-конфигурации
            if (!isSupportConfig(scope)) throw new UnsupportedOperationException(); 

            // создать источник каталогов
            IDirectoriesSource source = createConfigDirectories(scope); 

            // вернуть хранилище контейнеров
            return new DirectoriesStore(this, scope, source, extensions); 
        }
        // для хранилища в файле конфигурации 
        else if ((scope.equals(Scope.SYSTEM) && storeName.equals("FSLM")) || 
                 (scope.equals(Scope.USER)   && storeName.equals("FSCU")))
        {
            // проверить поддержку XML-конфигурации
            if (!isSupportConfig(scope)) throw new UnsupportedOperationException(); 

            // вернуть хранилище контейнеров
            return createConfigStore(scope);
        }
        // при ошибке выбросить исключение
        throw new IllegalArgumentException(); 
    }
    ///////////////////////////////////////////////////////////////////////
	// Поддержка XML-конфигурации
	///////////////////////////////////////////////////////////////////////
    private boolean isSupportConfig(Scope scope)
    {
        // получить загрузчик классов
        ClassLoader classLoader = ClassLoader.getSystemClassLoader(); 
        try { 
            // проверить наличие класса
            classLoader.loadClass("aladdin.capi.software.ConfigStore"); 
        }
        // обработать возможную ошибку
        catch (ClassNotFoundException e) { return false; }
        
        // получить профиль пользователя
        String directory = scope.equals(Scope.SYSTEM) ? 
            OS.INSTANCE.getSharedFolder() : OS.INSTANCE.getUserFolder(); 
        
        // указать используемый каталог
        directory = String.format("%1$s%2$s%3$s%4$s%5$s", 
            directory, File.separator, "Aladdin", File.separator, "CAPI"
        ); 
        // при отсутствии каталогов
        File fileDirectory = new File(directory); if (!fileDirectory.exists())
        {
            // создать каталоги
            try { fileDirectory.mkdirs(); } catch (Throwable e) { return false; }
        }
        return true; 
    }
    private SecurityStore createConfigStore(Scope scope)
    {
        // указать имя файла конфигурации
        String configName = String.format(
            "Aladdin%1$sCAPI%2$s%3$s.config", File.separator, File.separator, type
        ); 
        // получить загрузчик классов
        ClassLoader classLoader = ClassLoader.getSystemClassLoader(); 
        try { 
            // загрузить класс
            @SuppressWarnings({"rawtypes"}) 
            Class classConfigStore = classLoader.loadClass(
                "aladdin.capi.software.ConfigStore"
            ); 
            // получить метод класса
            @SuppressWarnings({"rawtypes", "unchecked"}) 
            Constructor constructor = classConfigStore.getConstructor(
                CryptoProvider.class, Scope.class, String.class
            ); 
            // выполнить конструктор
            return (SecurityStore)constructor.newInstance(this, scope, configName); 
        }
        // обработать возможное исключение
        catch (ClassNotFoundException    e) { throw new RuntimeException(e); }
        catch (NoSuchMethodException     e) { throw new RuntimeException(e); }
        catch (InstantiationException    e) { throw new RuntimeException(e); }
        catch (IllegalAccessException    e) { throw new RuntimeException(e); }
        catch (InvocationTargetException e) { throw new RuntimeException(e); }
    }
    private IDirectoriesSource createConfigDirectories(Scope scope)
    {
        // указать имя файла конфигурации
        String configName = String.format(
            "Aladdin%1$sCAPI%2$s%3$s.config", File.separator, File.separator, type
        ); 
        // получить загрузчик классов
        ClassLoader classLoader = ClassLoader.getSystemClassLoader(); 
        try { 
            // загрузить класс
            @SuppressWarnings({"rawtypes"}) 
            Class classConfigStore = classLoader.loadClass(
                "aladdin.capi.software.ConfigDirectories"
            ); 
            // получить метод класса
            @SuppressWarnings({"rawtypes", "unchecked"}) 
            Constructor constructor = classConfigStore.getConstructor(
                Scope.class, String.class
            ); 
            // выполнить конструктор
            return (IDirectoriesSource)constructor.newInstance(scope, configName); 
        }
        // обработать возможное исключение
        catch (ClassNotFoundException    e) { throw new RuntimeException(e); }
        catch (NoSuchMethodException     e) { throw new RuntimeException(e); }
        catch (InstantiationException    e) { throw new RuntimeException(e); }
        catch (IllegalAccessException    e) { throw new RuntimeException(e); }
        catch (InvocationTargetException e) { throw new RuntimeException(e); }
    }
	///////////////////////////////////////////////////////////////////////
	// Управление контейнерами
	///////////////////////////////////////////////////////////////////////
	public Container createContainer(IRand rand, ContainerStore store, 
        ContainerStream stream, String password, String keyOID) throws IOException
    {
		// операция не поддерживается
		throw new UnsupportedOperationException();
    }
	public Container openContainer(ContainerStore store, 
        ContainerStream stream) throws IOException
	{
		// операция не поддерживается
		throw new UnsupportedOperationException();
    }
	///////////////////////////////////////////////////////////////////////
	// Управление алгоритмами
	///////////////////////////////////////////////////////////////////////

    // поддерживаемые ключи
	@Override public SecretKeyFactory[] secretKeyFactories() 
    {
        // вернуть поддерживаемые ключи
        return factories.secretKeyFactories(); 
    }
    // поддерживаемые ключи
	@Override public KeyFactory[] keyFactories() 
    {
        // вернуть поддерживаемые ключи
        return factories.keyFactories(); 
    }
	// создать алгоритм генерации ключей
	@Override protected aladdin.capi.KeyPairGenerator createAggregatedGenerator(
        Factory outer, SecurityObject scope, IRand rand, 
        String keyOID, IParameters parameters) throws IOException
	{
        // проверить тип хранилища
        if (scope != null && !(scope instanceof ContainerStore)) return null; 
        
		// создать программный алгоритм генерации ключей
		return factories.createAggregatedGenerator(outer, null, rand, keyOID, parameters); 
	}
	// cоздать алгоритм для параметров
	@Override protected IAlgorithm createAggregatedAlgorithm(Factory outer, 
        SecurityStore scope, AlgorithmIdentifier parameters, 
        Class<? extends IAlgorithm> type) throws IOException
	{
        // проверить тип хранилища
        if (scope != null && !(scope instanceof ContainerStore)) return null; 
        
		// cоздать программный алгоритм для параметров
		return factories.createAggregatedAlgorithm(outer, null, parameters, type); 
	}
	///////////////////////////////////////////////////////////////////////
	// Управление контейнерами в памяти
	///////////////////////////////////////////////////////////////////////
    public Container createMemoryContainer(IRand rand, 
        MemoryStream stream, String password, String keyOID) throws IOException
	{
        // открыть хранилище
        try (SecurityStore store = openStore(Scope.SYSTEM, "MEMORY"))
        {
            // создать контейнер
            return (Container)store.createObject(rand, stream, password, keyOID); 
        }
    }
	public final Container openMemoryContainer(
        MemoryStream stream, String access, String password) throws IOException
	{
        // открыть хранилище
        try (SecurityStore store = openStore(Scope.SYSTEM, "MEMORY"))
        {
            // открыть контейнер
            try (Container container = (Container)store.openObject(stream, access)) 
            {
                // установить пароль
                if (password != null) container.setPassword(password); 
                
                // вернуть контейнер
                container.addRef(); return container; 
            }
        }
    }
	///////////////////////////////////////////////////////////////////////
	// Открыть каталог файловых контейнеров
	///////////////////////////////////////////////////////////////////////
	public final SecurityStore openDirectoryStore(
        String directory, String access) throws IOException
	{
	    // указать файловое хранилище
	    try (SecurityStore store = new DirectoriesStore(
            this, Scope.USER, new String[] { directory }, extensions))
        {
            // открыть каталог
            return (SecurityStore)store.openObject(directory, access); 
        }
    }
    public byte[][] enumerateDirectoryContainers(
        String directory, Container.Predicate filter) throws IOException
	{
		// создать список сертификатов
		List<byte[]> containers = new ArrayList<byte[]>();
 
        // открыть каталог контейнеров
        try (SecurityStore store = openDirectoryStore(directory, "r"))
        { 
            // для всех контейнеров PKCS12
	        for (String fileName : store.enumerateObjects())
	        {
                // открыть файл
                try (RandomAccessFile file = new RandomAccessFile(fileName, "r")) 
                {
                    // выделить буфер требуемого размера
                    byte[] content = new byte[(int)file.length()]; 
                    
                    // прочитать данные в буфер 
                    file.read(content, 0, content.length); 
                
                    // открыть контейнер
                    try (aladdin.capi.Container container = 
                        (aladdin.capi.Container)store.openObject(fileName, "r"))
                    {
                        // добавить содержимое контейнера в список
                        if (filter.test(container)) containers.add(content);
                    }
                }
                catch (Throwable e) {} 
	        }
            // вернуть список контейнеров
	        return containers.toArray(new byte[containers.size()][]); 
        }
	}
}
