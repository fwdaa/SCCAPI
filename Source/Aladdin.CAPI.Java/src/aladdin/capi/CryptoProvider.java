package aladdin.capi;
import aladdin.*;
import java.io.*;
import java.util.*; 

///////////////////////////////////////////////////////////////////////////
// Криптографический провайдер
///////////////////////////////////////////////////////////////////////////
public abstract class CryptoProvider extends Factory implements IProvider, IRandFactory 
{
    // имя группы провайдера
    public String group() { return name(); }
    // имя провайдера
    @Override public abstract String name(); 
        
	// перечислить хранилища объектов
	@Override public abstract String[] enumerateStores(Scope scope); 
    // получить хранилище объекта
    @Override public abstract SecurityStore openStore(
        Scope scope, String storeName) throws IOException;     
    
    ///////////////////////////////////////////////////////////////////////
    // Группы провайдеров
    ///////////////////////////////////////////////////////////////////////
    public static Iterable<CryptoProvider> getProviderGroups(Iterable<CryptoProvider> providers) 
    { 
        // создать список провайдеров
        List<CryptoProvider> providerGroups = new ArrayList<CryptoProvider>(); 

        // создать список групп
        List<String> groups = new ArrayList<String>(); 

        // для всех провайдеров
        for (CryptoProvider provider : providers)
        {
            // проверить отсутствие группы
            if (groups.contains(provider.group())) continue; 

            // добавить провайдер
            providerGroups.add(provider); groups.add(provider.group()); 
        }
        return providerGroups; 
    } 
    ///////////////////////////////////////////////////////////////////////
    // Генерация случайных данных
    ///////////////////////////////////////////////////////////////////////
    
    // фабрика генераторов случайных данных
    public IRandFactory createRandFactory(SecurityObject scope, boolean strong) 
    { 
        // фабрика генераторов случайных данных
        return RefObject.addRef(this); 
    }
    // создать генератор случайных данных
    public final IRand createRand(SecurityObject scope, Object window) throws IOException
    {
        // получить фабрику генераторов случайных данных
        try (IRandFactory randFactory = createRandFactory(scope, window != null)) 
        {
            // создать генератор случайных данных
            return randFactory.createRand(window); 
        }
    }
    // создать генератор случайных данных
    @Override public IRand createRand(Object window) throws IOException 
    { 
        // создать генератор случайных данных
        return new Rand(window); 
    } 
    ///////////////////////////////////////////////////////////////////////
    // Список генерируемых ключей
    ///////////////////////////////////////////////////////////////////////
    public String[] generatedKeys(SecurityStore store) 
    { 
        // получить поддерживаемые ключи
        List<String> keyOIDs = new ArrayList<String>(keyFactories().keySet()); 
        
        // вернуть поддерживаемые ключи
        return keyOIDs.toArray(new String[keyOIDs.size()]); 
    } 
    ///////////////////////////////////////////////////////////////////////
	// Иерархическое перечисление объектов
    ///////////////////////////////////////////////////////////////////////
	@Override public final SecurityInfo[] enumerateAllObjects(Scope scope)
    {
        // создать список описаний объектов
        Map<String, SecurityInfo> infos = new HashMap<String, SecurityInfo>(); 

        // при перечислении системных объектов
        if (scope == Scope.ANY || scope == Scope.SYSTEM)
        {
            // для всех системных хранилищ верхнего уровня
            for (String storeName : enumerateStores(Scope.SYSTEM))
            {
                // открыть хранилище
                try (SecurityStore store = openStore(Scope.SYSTEM, storeName))
                {
                    // для всех объектов
                    for (SecurityInfo info : store.enumerateAllObjects())
                    {
                        // добавить объект в список
                        if (!infos.containsKey(info.fullName())) infos.put(info.fullName(), info); 
                    }
                }
                catch (Throwable e) {}
            }
        }
        // при перечислении пользовательских объектов
        if (scope == Scope.ANY || scope == Scope.USER)
        {
            // для всех пользовательских хранилищ верхнего уровня
            for (String storeName : enumerateStores(Scope.USER))
            {
                // открыть хранилище
                try (SecurityStore store = openStore(Scope.USER, storeName))
                {
                    // для всех объектов
                    for (SecurityInfo info : store.enumerateAllObjects())
                    {
                        // добавить объект в список
                        if (!infos.containsKey(info.fullName())) infos.put(info.fullName(), info); 
                    }
                }
                catch (Throwable e) {}
            }
        }
        // выделить список требуемого размера
        SecurityInfo[] list = new SecurityInfo[infos.size()]; int i = 0; 
        
        // заполнить список описаний объектов
        for (SecurityInfo info : infos.values()) list[i++] = info; return list; 
    }
}
