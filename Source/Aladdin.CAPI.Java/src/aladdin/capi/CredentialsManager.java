package aladdin.capi;
import java.util.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Кэш реквизитов пользователей
///////////////////////////////////////////////////////////////////////////
public final class CredentialsManager implements Closeable
{
	// кэш аутентификационных данных (контейнер -> пользователь -> тип -> реквизиты)
	private final Map<SecurityInfo, Map<String, Map<Class<? extends Credentials>, Credentials>>> cache; 

    // конструктор
    public CredentialsManager() 
    { 
    	// создать кэш аутентификационных данных
		cache = new HashMap<SecurityInfo, Map<String, Map<Class<? extends Credentials>, Credentials>>>(); 
	} 
	// освободить ресурсы
	@Override public void close() 
	{ 
		// для каждого контейнера
		for (SecurityInfo info : cache.keySet())
        {
			// перейти на требуемый контейнер
			Map<String, Map<Class<? extends Credentials>, Credentials>> containerCache = cache.get(info); 

			// для каждого пользователя
			for (String user : containerCache.keySet())
            {
        		// перейти на требуемого пользователя
				Map<Class<? extends Credentials>, Credentials> userCache = containerCache.get(user); 

				// очистить реквизиты пользователя
				userCache.clear(); 
            }
			// очистить кэш пользователей
			containerCache.clear(); 
        }
		// очистить кэш контейнеров
		cache.clear(); 
	} 
	// найти аутентификационные данные
	public Credentials getData(SecurityInfo info, String user, Class<? extends Credentials> type)
	{
		// проверить наличие контейнера
        if (info.name == null || !cache.containsKey(info)) return null; 

		// перейти на требуемый контейнер
		Map<String, Map<Class<? extends Credentials>, Credentials>> containerCache = cache.get(info); 

		// проверить наличие пользователя
		if (!containerCache.containsKey(user)) return null; 

		// перейти на требуемого пользователя
		Map<Class<? extends Credentials>, Credentials> userCache = containerCache.get(user); 

		// вернуть реквизиты пользователя
		return (userCache.containsKey(type)) ? userCache.get(type) : null; 
	}
	// добавить аутентификационные данные в кэш
	public void setData(SecurityInfo info, String user, Credentials credentials) 
	{
        // проверить указание имени
        if (info.name == null) return; Map<Class<? extends Credentials>, Credentials> userCache = null; 
			
        // инициализировать переменную
		Map<String, Map<Class<? extends Credentials>, Credentials>> containerCache = null; 

		// перейти на кэш контейнера
		if (cache.containsKey(info)) containerCache = cache.get(info); 
        else {
			// создать новый элемент
			containerCache = new HashMap<String, Map<Class<? extends Credentials>, Credentials>>(); 

			// добавить новый элемент
			cache.put(info, containerCache); 
        }
		// перейти на кэш пользователя
		if (containerCache.containsKey(user)) userCache = containerCache.get(user); 
		else { 
			// создать новый элемент
			userCache = new HashMap<Class<? extends Credentials>, Credentials>(); 

			// добавить новый элемент
			containerCache.put(user, userCache); 
		}
		// добавить или переустановить реквизиты
        userCache.put(credentials.getClass(), credentials); 
	} 
	// удалить аутентификационные данные из кэша
    public void clearData(SecurityInfo info, String user, Class<? extends Credentials> type) 
    { 
		// проверить наличие контейнера
		if (info.name == null || !cache.containsKey(info)) return; 

		// перейти на требуемый контейнер
		Map<String, Map<Class<? extends Credentials>, Credentials>> containerCache = cache.get(info); 

		// проверить наличие пользователя
		if (!containerCache.containsKey(user)) return; 

		// перейти на требуемого пользователя
		Map<Class<? extends Credentials>, Credentials> userCache = containerCache.get(user); 

		// удалить реквизиты пользователя
		if (userCache.containsKey(type)) userCache.remove(type); 
    }
	// удалить аутентификационные данные из кэша
    public void clearData(SecurityInfo info) 
    { 
		// проверить наличие контейнера
		if (info.name == null || !cache.containsKey(info)) return; 

		// удалить реквизиты контейнера
		cache.remove(info); 
	}
} 
