package aladdin.capi;
import aladdin.*; 
import aladdin.capi.pbe.*; 
import aladdin.asn1.iso.*; 
import java.util.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Объединение фабрик алгоритмов
///////////////////////////////////////////////////////////////////////////
public class Factories extends Factory implements Iterable<Factory>
{
    // фабрики алгоритмов
    private final List<Factory> factories; private final List<CryptoProvider> providers;

	// конструктор
	public Factories(boolean software, Factory... factories) 
    { 
        // сохранить переданные параметры
        this(software, Arrays.asList(factories)); 
    }
	// конструктор
	public Factories(boolean software, Iterable<Factory> factories)
	{
		// создать список фабрик алгоритмов
		this.factories = new ArrayList<Factory>(); 
        
        // создать список провайдеров
        this.providers = new ArrayList<CryptoProvider>(); 
        
		// заполнить список фабрик алгоритмов
        fillFactories(software, factories);
	}
    @SuppressWarnings({"unchecked"}) 
    private void fillFactories(boolean software, Iterable<Factory> factories)
    {
        // для всех фабрик алгоритмов
        for (Factory factory : factories)
        {
            // для набора фабрик
            if (factory instanceof Iterable)
            {
                // перечислить фабрики набора
                fillFactories(software, (Iterable<Factory>)factory);
            }
            else {
                // добавить фабрику в список
                this.factories.add(RefObject.addRef(factory)); 
                
                // для криптографического провайдера
                if (!software && (factory instanceof CryptoProvider))
                {
                    // добавить провайдер в список
                    this.providers.add((CryptoProvider)factory); 
                }
            }
        }
    }
    // освободить используемые ресурсы
    @Override protected void onClose() throws IOException
    {
        // для всех фабрик алгоритмов
		for (Factory factory : factories) 
        try {
            // освободить используемые ресурсы
            RefObject.release(factory);
        }
        // вызвать базовую функцию
        catch (Throwable e) {} super.onClose();
    }
    ///////////////////////////////////////////////////////////////////////
    // Свойства набора фабрик
    ///////////////////////////////////////////////////////////////////////
    
    // криптографические провайдеры
    public final List<CryptoProvider> providers() { return providers; } 

    // группы провайдеров
    public final List<CryptoProvider> providerGroups() 
    { 
        // создать список провайдеров
        List<CryptoProvider> providers = new ArrayList<CryptoProvider>(); 

        // создать список групп
        List<String> groups = new ArrayList<String>(); 

        // для всех провайдеров
        for (CryptoProvider provider : this.providers)
        {
            // проверить отсутствие группы
            if (groups.contains(provider.group())) continue; 

            // добавить провайдер
            providers.add(provider); groups.add(provider.group()); 
        }
        return providers; 
    } 
    // перечислитель внутренних фабрик
	@Override public java.util.Iterator<Factory> iterator() { return factories.iterator(); }
    
	// получить элемент коллекции
	public Factory get(int i) { return factories.get(i); }

	// размер коллекции
	public int length() { return factories.size(); } 

    ///////////////////////////////////////////////////////////////////////
    // Поддерживаемые ключи
    ///////////////////////////////////////////////////////////////////////
	@Override public SecretKeyFactory[] secretKeyFactories() 
    { 
        // создать список поддерживаемых ключей
        List<SecretKeyFactory> keyFactories = new ArrayList<SecretKeyFactory>(); 
        
        // для всех фабрик алгоритмов
        for (Factory factory : factories)
        {
            // добавить поддерживаемые ключи
            keyFactories.addAll(Arrays.asList(factory.secretKeyFactories())); 
        }
        // вернуть список поддерживаемых ключей
        return keyFactories.toArray(new SecretKeyFactory[keyFactories.size()]); 
    }
	@Override public KeyFactory[] keyFactories() 
    { 
        // создать список поддерживаемых ключей
        Map<String, KeyFactory> keyFactories = new HashMap<String, KeyFactory>(); 
        
        // для всех фабрик алгоритмов
        for (Factory factory : factories)
        {
            // для всех фабрик ключей
            for (KeyFactory keyFactory : factory.keyFactories())
            {
                // при отсутствии фабрики ключей
                if (!keyFactories.containsKey(keyFactory.keyOID()))
                {
                    // добавить фабрику ключей
                    keyFactories.put(keyFactory.keyOID(), keyFactory); 
                }
            }
        }
        // получить список фабрик
        Collection<KeyFactory> collection = keyFactories.values(); 
        
        // вернуть список фабрик
        return collection.toArray(new KeyFactory[collection.size()]); 
    }
	///////////////////////////////////////////////////////////////////////
    // Используемые алгоритмы по умолчанию
	///////////////////////////////////////////////////////////////////////
    @Override public PBECulture getCulture(PBEParameters parameters, String keyOID) 
    {
        // для всех фабрик алгоритмов
        for (Factory factory : factories)
        {
            // получить алгоритмы по умолчанию
            PBECulture culture = factory.getCulture(parameters, keyOID); 

            // проверить наличие алгоритмов
            if (culture != null) return culture; 
        }
        return null; 
    }
	///////////////////////////////////////////////////////////////////////
    // Используемые алгоритмы по умолчанию
	///////////////////////////////////////////////////////////////////////
    @Override public Culture getCulture(SecurityStore scope, String keyOID) 
    {
        // для всех программных фабрик алгоритмов
        if (scope == null) for (Factory factory : factories)
        {
            // проверить тип фабрики
            if (factory instanceof CryptoProvider) continue; 

            // получить алгоритмы по умолчанию
            Culture culture = factory.getCulture(scope, keyOID); 
                
            // проверить наличие алгоритмов
            if (culture != null) return culture; 
        }
        // для провайдера алгоритмов
        else if (scope.provider() instanceof CryptoProvider)
        { 
            // выполнить преобразование типа
            CryptoProvider provider = (CryptoProvider)scope.provider(); 

            // получить алгоритмы по умолчанию
            Culture culture = provider.getCulture(scope, keyOID); 
                
            // проверить наличие алгоритмов
            if (culture != null) return culture; 
        }
        return null; 
    }
    ///////////////////////////////////////////////////////////////////////
    // Создать алгоритм генерации ключей
    ///////////////////////////////////////////////////////////////////////
    @Override public KeyPairGenerator createAggregatedGenerator(
        Factory outer, SecurityObject scope, IRand rand, 
        String keyOID, IParameters parameters) throws IOException
    {
        // для всех программных фабрик алгоритмов
        if (scope == null) for (Factory factory : factories)
        {
            // проверить тип фабрики
            if (factory instanceof CryptoProvider) continue; 

            // создать алгоритм генерации ключей
            KeyPairGenerator generator = factory.createAggregatedGenerator(
                outer, scope, rand, keyOID, parameters
            );
            // проверить наличие алгоритма
            if (generator != null) return generator;
        }
        // для провайдера алгоритмов
        else if (scope.provider() instanceof CryptoProvider)
        { 
            // выполнить преобразование типа
            CryptoProvider provider = (CryptoProvider)scope.provider(); 

            // создать алгоритм генерации ключей
            KeyPairGenerator generator = provider.createAggregatedGenerator(
                outer, scope, rand, keyOID, parameters
            );
            // проверить наличие алгоритма
            if (generator != null) return generator;
        }
        return null; 
    }
    ///////////////////////////////////////////////////////////////////////
    // Создать алгоритм
    ///////////////////////////////////////////////////////////////////////
    @Override public IAlgorithm createAggregatedAlgorithm(Factory outer, 
        SecurityStore scope, AlgorithmIdentifier parameters, 
        Class<? extends IAlgorithm> type) throws IOException
    {
        // для всех программных фабрик алгоритмов
        if (scope == null) for (Factory factory : factories)
        {
            // проверить тип фабрики
            if (factory instanceof CryptoProvider) continue; 
                
            // создать алгоритм
            IAlgorithm algorithm = factory.createAggregatedAlgorithm(
                outer, scope, parameters, type
            );
            // проверить наличие алгоритма
            if (algorithm != null) return algorithm;
        }
        // для провайдера алгоритмов
        else if (scope.provider() instanceof CryptoProvider)
        { 
            // выполнить преобразование типа
            CryptoProvider provider = (CryptoProvider)scope.provider(); 

            // создать алгоритм
            IAlgorithm algorithm = provider.createAggregatedAlgorithm(
                outer, scope, parameters, type
            );
            // проверить наличие алгоритма
            if (algorithm != null) return algorithm;
        }
        return null; 
    }
}
