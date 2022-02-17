package aladdin.capi;
import aladdin.*; 
import aladdin.capi.pbe.*;
import aladdin.capi.environment.*;
import java.lang.reflect.*; 
import java.io.*; 
import java.net.*; 
import java.util.*; 
import org.w3c.dom.*;

///////////////////////////////////////////////////////////////////////////
// Криптографическая среда
///////////////////////////////////////////////////////////////////////////
public class CryptoEnvironment extends ExecutionContext
{
    // фабрики алгоритмов и криптопровайдеры
    private final Factories factories; private final List<CryptoProvider> providers;  
    // фабрики генераторов случайных данных
    private final List<ConfigRandFactory> randFactories; 
        
    // отображаемые имена ключей
    private final Map<String, String> names;
    // отображение идентификаторов ключей на имена расширений
    private final Map<String, String> mappings; 
    
    // расширения криптографических культур
    private final Map<String, CulturePlugin> plugins;

    // конструктор
	public CryptoEnvironment(String fileName) throws Exception
    {
		// прочитать среду из файла
		this(ConfigSection.fromFile(fileName));  
    } 
    // конструктор
    public CryptoEnvironment(Document document) throws IOException 
    {
		// прочитать среду из секции конфигурации
		this(new ConfigSection(document)); 
    }
    // конструктор
    public CryptoEnvironment(ConfigSection section) throws IOException
	{
        // инициализировать переменные
	    names      = new HashMap<String, String       >();
        mappings   = new HashMap<String, String       >();
        plugins    = new HashMap<String, CulturePlugin>();

		// создать список фабрик классов
		List<Factory> factories = new ArrayList<Factory>(); 
            
		// создать список фабрик генераторов
        randFactories = new ArrayList<ConfigRandFactory>(); 

		// для всех фабрик алгоритмов
		for (ConfigFactory element : section.factories())
		try { 
            // определить имя модуля и класс фабрики
            String classLoader = element.classLoader(); String className = element.className(); 
                
            // добавить фабрику классов
            factories.add((Factory)loadObject(classLoader, className)); 
        }
        catch (Throwable e) {}
        
        // объединить фабрики алгоритмов
        try { this.factories = new Factories(false, factories); }
        finally { 
            // освободить выделенные ресурсы
            for (Factory factory : factories) RefObject.release(factory);
        }
		// для генераторов случайных данных
		for (ConfigRand element : section.rands())
        try {  
            // определить имя модуля и класс генератора
            String classLoader = element.classLoader(); String className = element.className(); 
                
            // создать фабрику генераторов
            try (IRandFactory randFactory = (IRandFactory)loadObject(classLoader, className))
            { 
                // создать фабрику генераторов
                randFactories.add(new ConfigRandFactory(randFactory, element.critical())); 
            }
        }
        catch (Throwable e) {}
        
		// для всех типов криптографических культур
        for (ConfigPlugin element : section.plugins())
        try {
            // определить имя модуля и класс фабрики
            String classLoader = element.classLoader(); String className = element.className(); 

            // прочитать параметры шифрования по паролю
            PBEParameters pbeParameters = new PBEParameters(
                element.pbmSaltLength(), element.pbmIterations(),  
                element.pbeSaltLength(), element.pbeIterations() 
            ); 
            // загрузить расширение
            CulturePlugin plugin = (CulturePlugin)
                loadObject(classLoader, className, pbeParameters); 

            // сохранить расширение
            plugins.put(element.name(), plugin);
        }
        catch (Throwable e) {}
        
		// для всех допустимых ключей
		for (ConfigKey element : section.keys())
        try {
            // проверить наличие описания семейства
            if (!plugins.containsKey(element.plugin())) throw new NoSuchElementException();
                
            // добавить отображаемое имя
            names.put(element.oid(), element.name()); 

            // добавить отображение имени
            mappings.put(element.oid(), element.plugin()); 
        }
        // создать список криптопровайдеров
        catch (Throwable e) {} providers = new ArrayList<CryptoProvider>(); 
        
        // создать провайдер PKCS12
        CryptoProvider provider = new aladdin.capi.pkcs12.CryptoProvider(this, factories); 
             
        // заполнить список криптопровайдеров
        providers.add(provider); providers.addAll(this.factories.providers()); 
    }
	// загрузить объект
    @SuppressWarnings({"rawtypes"}) 
	private Object loadObject(String classLoader, String className, Object... args) throws Throwable
    {
        // получить имя файла 
        File fileName = new File(classLoader); URL url = fileName.toURI().toURL(); 
        
        // создать загрузчик типов
        ClassLoader loader = new URLClassLoader(
            new URL[] { url }, getClass().getClassLoader()
        );        
		// получить описание типа
		Class<?> type = loader.loadClass(className); 

        // создать список типов аргументов
        Class[] argTypes = new Class[args.length]; 

        // заполнить список типов аргументов
        for (int i = 0; i < args.length; i++) argTypes[i] = args[i].getClass(); 

        // получить описание конструктора
		Constructor constructor = type.getConstructor(argTypes); 
        
		// загрузить объект
		try { return constructor.newInstance(args); }

        // обработать исключение
        catch (InvocationTargetException e) { throw e.getTargetException(); }
	}
    // освободить используемые ресурсы
    @Override protected void onClose() throws IOException  
    {
        // для всех плагинов
        for (CulturePlugin plugin : plugins.values())
        {
            // освободить выделенные ресурсы
            plugin.release(); 
        }
        // для всех фабрик генераторов
        for (ConfigRandFactory randFactory : randFactories)
        {
            // освободить выделенные ресурсы
            randFactory.release(); 
        }
        // освободить выделенные ресурсы
        providers.get(0).release(); factories.release(); super.onClose(); 
    }
    ///////////////////////////////////////////////////////////////////////
    // Фабрики алгоритмов
    ///////////////////////////////////////////////////////////////////////
    
    // фабрики алгоритмов
    public final Factories factories() { return factories; }

    // криптопровайдеры
    public final Iterable<CryptoProvider> providers() { return providers; }

    // получить провайдер PKCS12
    public final aladdin.capi.pkcs12.CryptoProvider getPKCS12Provider()
    {
        // получить провайдер PKCS12
        return (aladdin.capi.pkcs12.CryptoProvider)providers.get(0); 
    }
    ///////////////////////////////////////////////////////////////////////
    // Параметры и отображаемое имя ключа
    ///////////////////////////////////////////////////////////////////////
    @Override public IParameters getParameters(IRand rand, String keyOID, KeyUsage keyUsage)
    {
        // проверить наличие расширения 
        if (!mappings.containsKey(keyOID)) throw new NoSuchElementException();

        // отобразить диалог выбора параметров ключа
        return plugins.get(mappings.get(keyOID)).getParameters(rand, keyOID, keyUsage);
    }
    public final String getKeyName(String keyOID)
    {
        // отображаемое имя идентификатора
        return names.containsKey(keyOID) ? names.get(keyOID) : keyOID;
    }
    ///////////////////////////////////////////////////////////////////////
    // Парольная защита для контейнера PKCS12
    ///////////////////////////////////////////////////////////////////////
    @Override public PBECulture getCulture(Object window, String keyOID)
    {
        // проверить наличие расширения 
        if (!mappings.containsKey(keyOID)) throw new NoSuchElementException();

        // получить соответствующий плагин
        CulturePlugin plugin = plugins.get(mappings.get(keyOID)); 

        // отобразить диалог выбора криптографической культуры
        if (window != null) return plugin.getCulture(window, keyOID); 
             
        // вернуть парольную защиту по умолчанию
        return factories.getCulture(plugin.pbeParameters(), keyOID); 
    }
    ///////////////////////////////////////////////////////////////////////
    // Cоздать генератор случайных данных
    ///////////////////////////////////////////////////////////////////////
    public final boolean hasHardwareRand() { return !randFactories.isEmpty(); }
        
    // создать генератор случайных данных
    @Override public IRand createRand(Object window) throws IOException
    {
        // для генераторов случайных данных
		for (ConfigRandFactory randFactory : randFactories)
		{
            // создать генератор
            IRand rand = randFactory.createRand(window); 
                
            // проверить создание генератора
            if (rand != null) return rand; 
        } 
        // для всех фабрик алгоритмов
        for (Factory factory : factories)
        {
            // проверить наличие провайдера
            if (!(factory instanceof CryptoProvider)) continue; 

            // преобразовать тип фабрики
            CryptoProvider provider = (CryptoProvider)factory;
            try { 
                // создать генератор случайных данных
                IRand rand = provider.createRand(window); 

                // проверить наличие алгоритма
                if (rand != null) return rand;
            }
            catch (Throwable e) {}
        }
        // создать генератор случайных данных
        return new Rand(window); 
    }
}
