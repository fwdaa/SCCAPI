using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis; 

namespace Aladdin.CAPI
{
    ///////////////////////////////////////////////////////////////////////////
    // Контекст выполнения
    ///////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
    public class ExecutionContext : RefObject, IRandFactory, PBE.IPBECultureFactory
    {
        // кэши аутентификации провайдеров
        private static Dictionary<String, CredentialsManager> providerCaches; 

        // конструктор
        static ExecutionContext()
        {
			// создать кэши аутентификации провайдеров
			providerCaches = new Dictionary<String, CredentialsManager>(); 
        }
		// освободить ресурсы
		public static void Clear() 
		{ 
			// для каждого провайдера
			foreach (string providerName in providerCaches.Keys)
            {
				// очистить кэш провайдера
				providerCaches[providerName].Dispose(); 
			}
			// очистить кэш провайдеров
			providerCaches.Clear();
		} 
        ///////////////////////////////////////////////////////////////////////////
        // Кэш реквизитов пользователей
        ///////////////////////////////////////////////////////////////////////////
        
		// получить кэш провайдера
		public static CredentialsManager GetProviderCache(string providerName)
        {
            // при наличии провайдера
			if (providerCaches.ContainsKey(providerName)) 
            {
                // вернуть кэш провайдера
                return providerCaches[providerName]; 
            }
            // создать кэш провайдера
			CredentialsManager cache = new CredentialsManager(); 

            // добавить кэш провайдера 
			providerCaches.Add(providerName, cache); return cache; 
        }
        // выполнить аутентификацию через кэш
        public static Credentials[] CacheAuthenticate(
            SecurityObject obj, string user, Type[] authenticationTypes)
        {
            // проверить указание типов аутентификации
            if (authenticationTypes == null || user == null) return null; bool success = true;

            // список выполненных аутентификаций
            List<Credentials> credentialsList = new List<Credentials>(); 

            // для всех проводимых аутентификаций
            foreach (Type authenticationType in authenticationTypes)
            {
                // получить сервис аутентификации
                AuthenticationService service = obj.GetAuthenticationService(user, authenticationType);

                // проверить наличие сервиса
                if (service == null) return null; SecurityObject target = service.Target;

                // получить кэш аутентификации
                CredentialsManager cache = GetProviderCache(target.Provider.Name); 
                    
                // получить данные из кэша
                Credentials credentials = cache.GetData(target.Info, user, authenticationType); 

                // проверить наличие данных в кэше
                if (credentials == null) return null; 
                try {
                    // выполнить аутентификацию и добавить аутентификацию в список
                    credentialsList.AddRange(credentials.Authenticate(obj)); 
                }
                // при ошибке удалить данные из кэша
                catch { cache.ClearData(target.Info, user, authenticationType); success = false; } 
            }
            // проверить прохождение всех аутентификаций
            return (success) ? credentialsList.ToArray() : null; 
        }
        ///////////////////////////////////////////////////////////////////////
		// Переопределяемые фунции
		///////////////////////////////////////////////////////////////////////
        
        // генератор случайных данных
        public virtual IRand CreateRand(object window) { return new Rand(window); } 

        // получить парольную защиту
        public virtual PBE.PBECulture GetCulture(object window, string keyOID)
        {
            // выбросить исключение
            throw new InvalidOperationException(); 
        }
    }
}
