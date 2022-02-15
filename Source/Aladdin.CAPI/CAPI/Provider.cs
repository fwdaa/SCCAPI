using System;
using System.IO;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis; 

namespace Aladdin.CAPI
{
	///////////////////////////////////////////////////////////////////////////
	// Провайдер объектов
	///////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
    public abstract class Provider : RefObject, IProvider
    {
        // имя провайдера 
        public abstract string Name { get; } 

		// перечислить хранилища объектов
		public abstract string[] EnumerateStores(Scope scope); 
        // получить хранилище объектов
        public abstract SecurityStore OpenStore(Scope scope, string storeName);     

        // перечислить все объекты
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
