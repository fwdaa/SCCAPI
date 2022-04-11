using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis; 

namespace Aladdin.CAPI
{
	///////////////////////////////////////////////////////////////////////////
	// Криптографический провайдер
	///////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
	public abstract class CryptoProvider : Factory, IProvider, IRandFactory
    {
        // имя группы провайдера
        public virtual string Group { get {  return Name; } }
        // имя провайдера
        public abstract string Name { get; } 

		// перечислить хранилища объектов
		public abstract string[] EnumerateStores(Scope scope); 
        // получить хранилище объектов
        public abstract SecurityStore OpenStore(Scope scope, string storeName); 

        ///////////////////////////////////////////////////////////////////////
        // Группы провайдеров
        ///////////////////////////////////////////////////////////////////////
        public static IEnumerable<CryptoProvider> 
            GetProviderGroups(IEnumerable<CryptoProvider> providers)
        { 
            // создать список провайдеров
            List<CryptoProvider> providerGroups = new List<CryptoProvider>(); 

            // создать список групп
            List<String> groups = new List<String>(); 

            // для всех провайдеров
            foreach (CryptoProvider provider in providers)
            {
                // проверить отсутствие группы
                if (groups.Contains(provider.Group)) continue; 

                // добавить провайдер
                providerGroups.Add(provider); groups.Add(provider.Group); 
            }
            return providerGroups; 
        } 
        ///////////////////////////////////////////////////////////////////////
        // Генерация случайных данных
        ///////////////////////////////////////////////////////////////////////
        
        // фабрика генераторов случайных данных
        public virtual IRandFactory CreateRandFactory(SecurityObject scope, bool strong) 
        { 
            // фабрика генераторов случайных данных
            return RefObject.AddRef(this); 
        }
        // создать генератор случайных данных
        public IRand CreateRand(SecurityObject scope, object window)
        {
            // получить фабрику генераторов случайных данных
            using (IRandFactory randFactory = CreateRandFactory(scope, window != null))
            { 
                // создать генератор случайных данных
                return randFactory.CreateRand(window); 
            }
        }
        // создать генератор случайных данных
        public virtual IRand CreateRand(object window) { return new Rand(window); } 

        ///////////////////////////////////////////////////////////////////////
        // Список генерируемых ключей
        ///////////////////////////////////////////////////////////////////////
        public virtual string[] GeneratedKeys(SecurityStore store) 
        { 
            // список генерируемых ключей
            return new List<String>(KeyFactories().Keys).ToArray(); 
        } 
        ///////////////////////////////////////////////////////////////////////
		// Иерархическое перечисление объектов
        ///////////////////////////////////////////////////////////////////////
		public virtual SecurityInfo[] EnumerateAllObjects(Scope scope)
        {
            // создать список описаний объектов
            Dictionary<String, SecurityInfo> infos = new Dictionary<String, SecurityInfo>(); 

            // при перечислении системных объектов
            if (scope == Scope.Any || scope == Scope.System)
            {
                // для всех системных хранилищ верхнего уровня
                foreach (string storeName in EnumerateStores(Scope.System))
                try {
                    // открыть хранилище
                    using (SecurityStore store = OpenStore(Scope.System, storeName))
                    {
                        // для всех объектов
                        foreach (SecurityInfo info in store.EnumerateAllObjects())
                        {
                            // добавить объект в список
                            if (!infos.ContainsKey(info.FullName)) infos.Add(info.FullName, info); 
                        }
                    }
                }
                catch {}
            }
            // при перечислении пользовательских объектов
            if (scope == Scope.Any || scope == Scope.User)
            {
                // для всех пользовательских хранилищ верхнего уровня
                foreach (string storeName in EnumerateStores(Scope.User))
                try {
                    // открыть хранилище
                    using (SecurityStore store = OpenStore(Scope.User, storeName))
                    {
                        // для всех объектов
                        foreach (SecurityInfo info in store.EnumerateAllObjects())
                        {
                            // добавить объект в список
                            if (!infos.ContainsKey(info.FullName)) infos.Add(info.FullName, info); 
                        }
                    }
                }
                catch {}
            }
            // вернуть список описаний объектов
            return new List<SecurityInfo>(infos.Values).ToArray(); 
        }
    }
}
