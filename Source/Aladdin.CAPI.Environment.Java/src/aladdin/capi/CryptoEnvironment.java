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
    private final List<IRandFactory> randFactories; private boolean hardwareRand; 
        
    // отображаемые имена ключей
    private final Map<String, String> names;
    // отображение идентификаторов ключей на имена расширений
    private final Map<String, String> mappings; 
    
    // расширения криптографических культур
    private final Map<String, GuiPlugin> plugins;

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
        plugins    = new HashMap<String, GuiPlugin>();

		// создать список фабрик классов
		List<Factory> factories = new ArrayList<Factory>(); 
            
		// создать список фабрик генераторов
        randFactories = new ArrayList<IRandFactory>(); hardwareRand = false; 

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
		for (ConfigRandFactory element : section.rands())
        try {  
            // создать фабрику генераторов
            if (element.gui()) randFactories.add(new GuiRandFactory(element)); 
            else {
                // определить имя модуля и класс генератора
                String classLoader = element.classLoader(); String className = element.className(); 
                
                // создать фабрику генераторов
                randFactories.add((IRandFactory)loadObject(classLoader, className)); hardwareRand = true; 
            }
        }
        catch (Throwable e) {}
        
		// для всех типов криптографических культур
        for (ConfigPlugin element : section.plugins())
        try {
            // загрузить расширение
            GuiPlugin plugin = new GuiPlugin(element);  

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
        for (GuiPlugin plugin : plugins.values())
        {
            // освободить выделенные ресурсы
            plugin.release(); 
        }
        // для всех фабрик генераторов
        for (IRandFactory randFactory : randFactories)
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
    @Override public IParameters getParameters(
        IRand rand, String keyOID, KeyUsage keyUsage) throws IOException
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
    @Override public PBECulture getCulture(Object window, String keyOID) throws IOException
    {
        // проверить наличие расширения 
        if (!mappings.containsKey(keyOID)) throw new NoSuchElementException();

        // получить соответствующий плагин
        GuiPlugin plugin = plugins.get(mappings.get(keyOID)); 

        // отобразить диалог выбора криптографической культуры
        if (window != null) return plugin.getCulture(window, keyOID); 
             
        // вернуть парольную защиту по умолчанию
        return factories.getCulture(plugin.pbeParameters(), keyOID); 
    }
    ///////////////////////////////////////////////////////////////////////
    // Cоздать генератор случайных данных
    ///////////////////////////////////////////////////////////////////////
    @Override public IRand createRand(Object window) throws IOException
    {
        // для генераторов случайных данных
		for (IRandFactory randFactory : randFactories)
		{
            // проверить допустимость фабрики
            if (window == null && randFactory instanceof GuiRandFactory) continue; 
            
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
    // признак наличия аппаратного генератора
    public final boolean hasHardwareRand() { return hardwareRand; }
}
