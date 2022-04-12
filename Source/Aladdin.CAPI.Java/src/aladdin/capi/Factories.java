package aladdin.capi;
import aladdin.*; 
import aladdin.asn1.*; 
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
            // для криптопровайдера
            else if (factory instanceof CryptoProvider)
            {
                if (!software)
                {
                    // добавить фабрику в список
                    this.factories.add(RefObject.addRef(factory)); 

                    // добавить провайдер в список
                    this.providers.add((CryptoProvider)factory); 
                }
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
    
    // криптографические провайдеры
    public final List<CryptoProvider> providers() { return providers; } 

    // перечислитель внутренних фабрик
	@Override public java.util.Iterator<Factory> iterator() { return factories.iterator(); }
    
	// получить элемент коллекции
	public Factory get(int i) { return factories.get(i); }

	// размер коллекции
	public int length() { return factories.size(); } 

    ///////////////////////////////////////////////////////////////////////
    // Поддерживаемые ключи
    ///////////////////////////////////////////////////////////////////////
	@Override public Map<String, KeyFactory> keyFactories() 
    { 
        // создать список поддерживаемых ключей
        Map<String, KeyFactory> keyFactories = new HashMap<String, KeyFactory>(); 
        
        // для всех фабрик алгоритмов
        for (Factory factory : factories)
        {
            // для всех поддерживаемых ключей
            for (Map.Entry<String, KeyFactory> entry : factory.keyFactories().entrySet())
            {
                // добавить фабрику в таблицу
                keyFactories.put(entry.getKey(), entry.getValue()); 
            }
        }
        return keyFactories; 
    }
    ///////////////////////////////////////////////////////////////////////
    // Создать алгоритм генерации ключей
    ///////////////////////////////////////////////////////////////////////
    @Override public KeyPairGenerator createAggregatedGenerator(
        Factory outer, SecurityObject scope, IRand rand, 
        String keyOID, IParameters parameters) throws IOException
    {
        if (scope == null) 
        {
            // для всех программных фабрик алгоритмов
            for (Factory factory : factories)
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
            // для всех программных провайдеров
            for (Factory factory : factories)
            {
                // проверить тип фабрики
                if (!(factory instanceof aladdin.capi.software.CryptoProvider)) continue; 

                // создать алгоритм генерации ключей
                KeyPairGenerator generator = factory.createAggregatedGenerator(
                    outer, scope, rand, keyOID, parameters
                );
                // проверить наличие алгоритма
                if (generator != null) return generator;
            }
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
        SecurityStore scope, String oid, IEncodable parameters, 
        Class<? extends IAlgorithm> type) throws IOException
    {
        if (scope == null) 
        {
            // для всех программных фабрик алгоритмов
            for (Factory factory : factories)
            {
                // проверить тип фабрики
                if (factory instanceof CryptoProvider) continue; 
                
                // создать алгоритм
                IAlgorithm algorithm = factory.createAggregatedAlgorithm(
                    outer, scope, oid, parameters, type
                );
                // проверить наличие алгоритма
                if (algorithm != null) return algorithm;
            }
            // для всех программных провайдеров
            for (Factory factory : factories)
            {
                // проверить тип фабрики
                if (!(factory instanceof aladdin.capi.software.CryptoProvider)) continue; 

                // создать алгоритм
                IAlgorithm algorithm = factory.createAggregatedAlgorithm(
                    outer, scope, oid, parameters, type
                );
                // проверить наличие алгоритма
                if (algorithm != null) return algorithm;
            }
        }
        // для провайдера алгоритмов
        else if (scope.provider() instanceof CryptoProvider)
        { 
            // выполнить преобразование типа
            CryptoProvider provider = (CryptoProvider)scope.provider(); 

            // создать алгоритм
            IAlgorithm algorithm = provider.createAggregatedAlgorithm(
                outer, scope, oid, parameters, type
            );
            // проверить наличие алгоритма
            if (algorithm != null) return algorithm;
        }
        return null; 
    }
}
