package aladdin.capi;
import aladdin.*; 
import aladdin.capi.pbe.*;
import aladdin.capi.environment.*;
import java.io.*; 
import java.util.*; 

///////////////////////////////////////////////////////////////////////////
// Криптографическая среда
///////////////////////////////////////////////////////////////////////////
public class CryptoEnvironment extends ExecutionContext implements IParametersFactory, ICultureFactory
{
    // фабрики алгоритмов и криптопровайдеры
    private final Factories factories; private final List<CryptoProvider> providers;  
    // фабрики генераторов случайных данных
    private final List<IRandFactory> randFactories; private boolean hardwareRand; 
        
    // расширения криптографических культур
    private final Map<String, GuiPlugin> plugins; private final PBEParameters pbeParameters; 
    
    // отображения по идентификаторам ключей
    private Map<String, String > keyNames;       // имена ключей
    private Map<String, String > keyPlugins;     // имена расширений
    private Map<String, Culture> keyCultures;    // параметры алгоритмов
    
    // криптографическая среда по умолчанию
    public static CryptoEnvironment getDefault(PBEParameters parameters) 
    { 
        // криптографическая среда по умолчанию
        return new CryptoEnvironment(Config.DEFAULT, parameters); 
    }
    // конструктор
    public CryptoEnvironment(ConfigSection section, PBEParameters pbeParameters)
	{
        // сохранить переданные параметры
        this.pbeParameters = pbeParameters; hardwareRand = false; 
        
        // указать загрузчик классов
        ClassLoader classLoader = ClassLoader.getSystemClassLoader(); 
        
        // инициализировать переменные
        plugins     = new HashMap<String, GuiPlugin>();
        keyNames    = new HashMap<String, String   >();
        keyPlugins  = new HashMap<String, String   >();
	    keyCultures = new HashMap<String, Culture  >();

		// создать список фабрик классов
		List<Factory> factories = new ArrayList<Factory>(); 
            
		// создать список фабрик генераторов
        randFactories = new ArrayList<IRandFactory>(); 

		// для всех фабрик алгоритмов
		for (ConfigFactory element : section.factories())
		try { 
            // определить класс фабрики
            String className = element.className(); 
                
            // добавить фабрику классов
            factories.add((Factory)Loader.loadClass(classLoader, className)); 
        }
        catch (Throwable e) {}
        
        // объединить фабрики алгоритмов
        try { this.factories = new Factories(false, factories); } 
        finally { 
            // для всех используемых фабрик
            for (Factory factory : factories) 
            {
                // освободить выделенные ресурсы
                try { RefObject.release(factory); } catch (Throwable e) {}
            }
        }
		// для генераторов случайных данных
		for (ConfigRandFactory element : section.rands())
        try {  
            // создать фабрику генераторов
            if (element.gui()) randFactories.add(new GuiRandFactory(element)); 
            else {
                // определить класс генератора
                String className = element.className(); 
                
                // создать фабрику генераторов
                randFactories.add((IRandFactory)Loader.loadClass(classLoader, className)); 
                
                hardwareRand = true; 
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
            // определить класс культуры
            String className = element.className(); 
            
            // добавить культуру в список
            keyCultures.put(element.oid(), (Culture)Loader.loadClass(classLoader, className)); 
            
            // сохранить имя ключа
            keyNames.put(element.oid(), element.name()); 

            // добавить имя расширения 
            keyPlugins.put(element.oid(), element.plugin()); 
        }
        // создать список криптопровайдеров
        catch (Throwable e) {} providers = new ArrayList<CryptoProvider>(); 
        
        // создать провайдер PKCS12
        CryptoProvider provider = new aladdin.capi.pkcs12.CryptoProvider(this, factories); 
             
        // заполнить список криптопровайдеров
        providers.add(provider); providers.addAll(this.factories.providers()); 
    }
    // освободить используемые ресурсы
    @Override protected void onClose() throws IOException  
    {
        // освободить выделенные ресурсы
        for (GuiPlugin plugin : plugins.values()) plugin.release(); 
        
        // освободить выделенные ресурсы
        for (IRandFactory randFactory : randFactories) randFactory.release();
        
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
        // определить имя плагина 
        String pluginName = getKeyPlugin(keyOID); 
        
        // проверить наличие расширения 
        if (!plugins.containsKey(pluginName)) throw new NoSuchElementException();

        // отобразить диалог выбора параметров ключа
        return plugins.get(pluginName).getParameters(rand, keyOID, keyUsage);
    }
    public final String getKeyName(String keyOID)
    {
        // отображаемое имя идентификатора
        return keyNames.containsKey(keyOID) ? keyNames.get(keyOID) : keyOID;
    }
    public final String getKeyPlugin(String keyOID)
    {
        // проверить наличие расширения 
        if (!keyPlugins.containsKey(keyOID)) throw new NoSuchElementException();

        // вернуть имя плагина 
        return keyPlugins.get(keyOID); 
    }
    ///////////////////////////////////////////////////////////////////////
    // Параметры алгоритмов по умолчанию
    ///////////////////////////////////////////////////////////////////////
    @Override public Culture getCulture(String keyOID)
    {
        // проверить наличие расширения 
        if (!keyCultures.containsKey(keyOID)) throw new NoSuchElementException();

        // вернуть параметры алгоритмов по умолчанию
        return keyCultures.get(keyOID); 
    }
    ///////////////////////////////////////////////////////////////////////
    // Парольная защита для контейнера PKCS12
    ///////////////////////////////////////////////////////////////////////
    @Override public PBECulture getPBECulture(Object window, String keyOID) throws IOException
    {
        // определить имя плагина 
        String pluginName = getKeyPlugin(keyOID); if (window != null) 
        {
            // проверить наличие расширения 
            if (!plugins.containsKey(pluginName)) throw new NoSuchElementException();
            
            // получить соответствующий плагин
            GuiPlugin plugin = plugins.get(pluginName); 

            // отобразить диалог выбора криптографической культуры
            return plugin.getPBECulture(window, keyOID); 
        }
        else {
            // указать параметры шифрования по паролю
            PBEParameters parameters = pbeParameters; 
            
            // проверить наличие расширения 
            if (plugins.containsKey(pluginName))
            {
                // получить параметры шифрования по паролю
                parameters = plugins.get(pluginName).pbeParameters(); 
            }
            // проверить наличие прараметров
            if (parameters == null) throw new IllegalStateException(); 
            
            // вернуть парольную защиту по умолчанию
            return getCulture(keyOID).pbe(parameters); 
        }
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
