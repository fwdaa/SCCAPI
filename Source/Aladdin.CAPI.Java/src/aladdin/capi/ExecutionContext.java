package aladdin.capi;
import aladdin.capi.pbe.*; 
import aladdin.*; 
import java.io.*; 
import java.util.*; 

///////////////////////////////////////////////////////////////////////////
// Контекст выполнения
///////////////////////////////////////////////////////////////////////////
public class ExecutionContext extends RefObject implements IRandFactory, IPBECultureFactory
{
    // кэши аутентификации провайдеров
    private static final Map<String, CredentialsManager> providerCaches; 

    // создать кэши аутентификации провайдеров
    static { providerCaches = new HashMap<String, CredentialsManager>(); }
    
	// освободить ресурсы
	public static void clear() 
	{ 
		// для каждого провайдера
		for (String providerName : providerCaches.keySet())
        {
			// очистить кэш провайдера
			providerCaches.get(providerName).close(); 
		}
		// очистить кэш провайдеров
		providerCaches.clear(); 
	} 
	// получить кэш провайдера
	public static CredentialsManager getProviderCache(String providerName)
    {
        // при наличии провайдера
        if (providerCaches.containsKey(providerName)) 
        {
            // вернуть кэш провайдера
            return providerCaches.get(providerName); 
        }
        // создать кэш провайдера
		CredentialsManager cache = new CredentialsManager(); 

        // добавить кэш провайдера 
		providerCaches.put(providerName, cache); return cache; 
    }
    // выполнить аутентификацию через кэш
    public static Credentials[] cacheAuthenticate(SecurityObject obj, 
        String user, Class<? extends Credentials>[] authenticationTypes)
    {
        // проверить указание типов аутентификации
        if (authenticationTypes == null) return null; 

        // проверить указание типа пользователя
        if (user == null) return null; boolean success = true; 

        // список выполненных аутентификаций
        List<Credentials> credentialsList = new ArrayList<Credentials>(); 

        // для всех проводимых аутентификаций
        for (Class<? extends Credentials> authenticationType : authenticationTypes)
        {
            // получить сервис аутентификации
            AuthenticationService service = obj.getAuthenticationService(user, authenticationType);
            
            // проверить наличие сервиса
            if (service == null) return null; SecurityObject target = service.target();

            // получить кэш аутентификации
            CredentialsManager cache = getProviderCache(target.provider().name()); 
            
            // получить данные из кэша
            Credentials credentials = cache.getData(target.info(), user, authenticationType); 

            // проверить наличие данных в кэше
            if (credentials == null) return null; 
            try {
                // выполнить аутентификацию и добавить аутентификацию в список
                credentialsList.addAll(Arrays.asList(credentials.authenticate(obj))); 
            }
            // при ошибке удалить данные из кэша
            catch (Throwable e) { cache.clearData(target.info(), user, authenticationType); success = false; } 
        }
        // вернуть результат аутентификаций
        return success ? credentialsList.toArray(new Credentials[credentialsList.size()]) : null; 
    }
    ///////////////////////////////////////////////////////////////////////
	// Переопределеяемые фунции
	///////////////////////////////////////////////////////////////////////
        
    // генератор случайных данных
    @Override public IRand createRand(Object window) throws IOException { return new Rand(window); } 
    
    // получить парольную защиту
    @Override public PBECulture getPBECulture(
        Object window, String keyOID) throws IOException
    {
        // выбросить исключение
        throw new IllegalStateException(); 
    }
}
