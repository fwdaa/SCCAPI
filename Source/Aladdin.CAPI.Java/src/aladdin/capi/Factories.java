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
    private final List<Factory> factories;

	// конструктор
	public Factories(Factory... factories) { this(Arrays.asList(factories)); }
    
	// конструктор
	public Factories(Iterable<Factory> factories)
	{
		// заполнить список фабрик алгоритмов
		this.factories = new ArrayList<Factory>(); fillFactories(factories);
	}
    @SuppressWarnings({"unchecked"}) 
    private void fillFactories(Iterable<Factory> factories)
    {
        // для всех фабрик алгоритмов
        for (Factory factory : factories)
        {
            // для набора фабрик
            if (factory instanceof Iterable)
            {
                // перечислить фабрики набора
                fillFactories((Iterable<Factory>)factory);
            }
            // добавить фабрику в список
            else this.factories.add(RefObject.addRef(factory)); 
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
        // поддерживаемые ключи
        return secretKeyFactories(null); 
    }
	public SecretKeyFactory[] secretKeyFactories(FactoryFilter filter) 
    { 
        // создать список поддерживаемых ключей
        List<SecretKeyFactory> keyFactories = new ArrayList<SecretKeyFactory>(); 
        
        // для всех фабрик алгоритмов
        for (Factory factory : factories)
        {
            // для допустимой фабрики
            if (filter == null || filter.isMatch(factory))
            {
                // добавить поддерживаемые ключи
                keyFactories.addAll(Arrays.asList(factory.secretKeyFactories())); 
            }
        }
        // вернуть список поддерживаемых ключей
        return keyFactories.toArray(new SecretKeyFactory[keyFactories.size()]); 
    }
	@Override public KeyFactory[] keyFactories() 
    { 
        // поддерживаемые ключи
        return keyFactories(null); 
    }
	public KeyFactory[] keyFactories(FactoryFilter filter) 
    { 
        // создать список поддерживаемых ключей
        List<KeyFactory> keyFactories = new ArrayList<KeyFactory>(); 
        
        // для всех фабрик алгоритмов
        for (Factory factory : factories)
        {
            // для допустимой фабрики
            if (filter == null || filter.isMatch(factory))
            {
                // добавить поддерживаемые ключи
                keyFactories.addAll(Arrays.asList(factory.keyFactories())); 
            }
        }
        // вернуть список поддерживаемых ключей
        return keyFactories.toArray(new KeyFactory[keyFactories.size()]); 
    }
	///////////////////////////////////////////////////////////////////////
    // Используемые алгоритмы по умолчанию
	///////////////////////////////////////////////////////////////////////
    @Override public Culture getCulture(SecurityStore scope, String keyOID) 
    {
        // получить алгоритмы по умолчанию
        return getCulture(scope, null, keyOID); 
    }
    public Culture getCulture(SecurityStore scope, FactoryFilter filter, String keyOID) 
    {
        // для программных алгоритмов
        if (scope == null || scope instanceof aladdin.capi.software.ContainerStore)
        {
            // указать фильтр программных фабрик
            FactoryFilter softwareFilter = new FactoryFilter.Software(filter);

            // для всех фабрик алгоритмов
            for (Factory factory : factories)
            {
                // для допустимой фабрики
                if (softwareFilter.isMatch(factory))
                {
                    // получить алгоритмы по умолчанию
                    Culture culture = factory.getCulture(scope, keyOID); 

                    // проверить наличие алгоритмов
                    if (culture != null) return culture; 
                }
            }
        }
        else {
            // указать фильтр провайдеров
            FactoryFilter providerFilter = new FactoryFilter.Provider(filter);

            // для всех фабрик алгоритмов
            for (Factory factory : factories)
            {
                // для допустимой фабрики
                if (providerFilter.isMatch(factory))
                {
                    // получить алгоритмы по умолчанию
                    Culture culture = factory.getCulture(scope, keyOID); 

                    // проверить наличие алгоритмов
                    if (culture != null) return culture; 
                }
            }
        }
        return null; 
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
    // Создать алгоритм генерации ключей
    ///////////////////////////////////////////////////////////////////////
    @Override protected KeyPairGenerator createAggregatedGenerator(
        Factory outer, SecurityObject scope, String keyOID, 
        IParameters parameters, IRand rand) throws IOException
	{
        // создать алгоритм генерации ключей
        return createAggregatedGenerator(outer, scope, null, keyOID, parameters, rand); 
	}
    public final KeyPairGenerator createAggregatedGenerator(
        Factory outer, SecurityObject scope, FactoryFilter filter,
        String keyOID, IParameters parameters, IRand rand) throws IOException
    {
        // для программных алгоритмов
        if (scope == null || scope instanceof aladdin.capi.software.Container)
        {
            // указать фильтр программных фабрик
            FactoryFilter softwareFilter = new FactoryFilter.Software(filter);

            // для всех фабрик алгоритмов
            for (Factory factory : factories)
            {
                // для допустимой фабрики
                if (softwareFilter.isMatch(factory))
                {
                    // создать алгоритм генерации ключей
                    KeyPairGenerator generator = factory.createAggregatedGenerator(
                        outer, scope, keyOID, parameters, rand
                    );
                    // проверить наличие алгоритма
                    if (generator != null) return generator;
                }
            }
        }
        // указать фильтр провайдеров
        FactoryFilter providerFilter = new FactoryFilter.Provider(filter);

        // для всех фабрик алгоритмов
        for (Factory factory : factories)
        {
            // для допустимой фабрики
            if (providerFilter.isMatch(factory))
            {
                // создать алгоритм генерации ключей
                KeyPairGenerator generator = factory.createAggregatedGenerator(
                    outer, scope, keyOID, parameters, rand
                );
                // проверить наличие алгоритма
                if (generator != null) return generator;
            }
        }
        return null; 
    }
    ///////////////////////////////////////////////////////////////////////
    // Создать алгоритм
    ///////////////////////////////////////////////////////////////////////
    @Override protected IAlgorithm createAggregatedAlgorithm(Factory outer, 
        SecurityStore scope, AlgorithmIdentifier parameters, 
        Class<? extends IAlgorithm> type) throws IOException
	{
        // создать алгоритм
        return createAggregatedAlgorithm(outer, scope, null, parameters, type); 
	}
    public final IAlgorithm createAggregatedAlgorithm(Factory outer, 
        SecurityStore scope, FactoryFilter filter, AlgorithmIdentifier parameters, 
        Class<? extends IAlgorithm> type) throws IOException
    {
        // для программных алгоритмов
        if (scope == null || scope instanceof aladdin.capi.software.ContainerStore)
        {
            // указать фильтр программных фабрик
            FactoryFilter softwareFilter = new FactoryFilter.Software(filter);

            // для всех фабрик алгоритмов
            for (Factory factory : factories)
            {
                // для допустимой фабрики
                if (softwareFilter.isMatch(factory))
                {
                    // создать алгоритм
                    IAlgorithm algorithm = factory.createAggregatedAlgorithm(
                        outer, scope, parameters, type
                    );
                    // проверить наличие алгоритма
                    if (algorithm != null) return algorithm;
                }
            }
        }
        // указать фильтр провайдеров
        FactoryFilter providerFilter = new FactoryFilter.Provider(filter);

        // для всех фабрик алгоритмов
        for (Factory factory : factories)
        {
            // для допустимой фабрики
            if (providerFilter.isMatch(factory))
            {
                // создать алгоритм
                IAlgorithm algorithm = factory.createAggregatedAlgorithm(
                    outer, scope, parameters, type
                );
                // проверить наличие алгоритма
                if (algorithm != null) return algorithm;
            }
        }
        return null; 
    }
}
