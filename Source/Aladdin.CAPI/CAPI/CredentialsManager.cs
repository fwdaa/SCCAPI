using System;
using System.Collections.Generic;

namespace Aladdin.CAPI
{
	///////////////////////////////////////////////////////////////////////////
	// Кэш реквизитов пользователей
	///////////////////////////////////////////////////////////////////////////
	public sealed class CredentialsManager : IDisposable
	{
		// кэш аутентификационных данных (контейнер -> пользователь -> тип -> реквизиты)
		private Dictionary<SecurityInfo, Dictionary<String, Dictionary<Type, Credentials>>> cache; 

        // конструктор
        public CredentialsManager() 
        { 
			// создать кэш аутентификационных данных
			cache = new Dictionary<SecurityInfo, Dictionary<String, Dictionary<Type, Credentials>>>(); 
		} 
		// освободить ресурсы
		public void Dispose() 
		{ 
			// для каждого контейнера
			foreach (SecurityInfo info in cache.Keys)
            {
				// перейти на требуемый контейнер
				Dictionary<String, Dictionary<Type, Credentials>> containerCache = cache[info]; 

				// для каждого пользователя
				foreach (string user in containerCache.Keys)
                {
					// перейти на требуемого пользователя
					Dictionary<Type, Credentials> userCache = containerCache[user]; 

					// очистить реквизиты пользователя
					userCache.Clear(); 
                }
				// очистить кэш пользователей
				containerCache.Clear(); 
            }
			// очистить кэш контейнеров
			cache.Clear(); 
		} 
		// найти аутентификационные данные
		public Credentials GetData(SecurityInfo info, string user, Type type)
		{
			// проверить наличие контейнера
            if (info.Name == null || !cache.ContainsKey(info)) return null; 

			// перейти на требуемый контейнер
			Dictionary<String, Dictionary<Type, Credentials>> containerCache = cache[info]; 

			// проверить наличие пользователя
			if (!containerCache.ContainsKey(user)) return null; 

			// перейти на требуемого пользователя
			Dictionary<Type, Credentials> userCache = containerCache[user]; 

			// вернуть реквизиты пользователя
			return (userCache.ContainsKey(type)) ? userCache[type] : null; 
		}
		// добавить аутентификационные данные в кэш
		public void SetData(SecurityInfo info, string user, Credentials credentials) 
		{
            // проверить указание имени
            if (info.Name == null) return; Dictionary<Type, Credentials> userCache = null; 
			
			// инициализировать переменную
			Dictionary<String, Dictionary<Type, Credentials>> containerCache = null; 

			// перейти на кэш контейнера
			if (cache.ContainsKey(info)) containerCache = cache[info]; 
            else {
				// создать новый элемент
				containerCache = new Dictionary<String, Dictionary<Type, Credentials>>(); 

				// добавить новый элемент
				cache.Add(info, containerCache); 
            }
			// перейти на кэш пользователя
			if (containerCache.ContainsKey(user)) userCache = containerCache[user]; 
			else { 
				// создать новый элемент
				userCache = new Dictionary<Type, Credentials>(); 

				// добавить новый элемент
				containerCache.Add(user, userCache); 
			}
			// определить тип реквизитов
			Type type = credentials.GetType(); 

			// переустановить реквизиты
            if (userCache.ContainsKey(type)) userCache[type] = credentials; 

            // добавить реквизиты
            else userCache.Add(type, credentials); 
		} 
		// удалить аутентификационные данные из кэша
        public void ClearData(SecurityInfo info, string user, Type type) 
        { 
			// проверить наличие контейнера
			if (info.Name == null || !cache.ContainsKey(info)) return; 

			// перейти на требуемый контейнер
			Dictionary<String, Dictionary<Type, Credentials>> containerCache = cache[info]; 

			// проверить наличие пользователя
			if (!containerCache.ContainsKey(user)) return; 

			// перейти на требуемого пользователя
			Dictionary<Type, Credentials> userCache = containerCache[user]; 

			// удалить реквизиты пользователя
			if (userCache.ContainsKey(type)) userCache.Remove(type); 
        }
		// удалить аутентификационные данные из кэша
        public void ClearData(SecurityInfo info) 
        { 
			// проверить наличие контейнера
			if (info.Name == null || !cache.ContainsKey(info)) return; 

			// удалить реквизиты контейнера
			cache.Remove(info); 
		}
	} 
}
