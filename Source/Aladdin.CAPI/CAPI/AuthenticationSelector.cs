using System;
using System.Collections.Generic;
using System.IO;

namespace Aladdin.CAPI
{
    ///////////////////////////////////////////////////////////////////////////
    // Выбор аутентификации
    ///////////////////////////////////////////////////////////////////////////
    public class AuthenticationSelector
    {
        // конструктор
        public AuthenticationSelector(string user) 
        
            // сохранить переданные параметры
            { this.user = user; } private string user; 

        // тип пользователя
        public string User { get { return user; }} 

        ///////////////////////////////////////////////////////////////////////
        // Получить список аутентификаций
        ///////////////////////////////////////////////////////////////////////
        public Authentication[] GetAuthentications(SecurityObject obj)
        {
            // создать список типов возможных аутентификаций
            List<Type> authenticationTypes = new List<Type>(); 

            // для всех допустимых аутентификаций
            foreach (Type authenticationType in obj.GetAuthenticationTypes(User))
            {
                // получить сервис аутентификации
                AuthenticationService service = obj.GetAuthenticationService(
                    User, authenticationType
                ); 
                // проверить установку аутентификации
                if (service.CanLogin) authenticationTypes.Add(authenticationType); 
            }
            // проверить наличие аутентификации
            if (authenticationTypes.Count == 0) return new Authentication[0]; 
                    
            // получить возможные аутентификации
            return GetAuthentications(obj, authenticationTypes); 
        }
        // получить требуемую аутентификацию
        protected virtual Authentication[] GetAuthentications(
            SecurityObject obj, List<Type> authenticationTypes) { return new Authentication[0]; } 

        ///////////////////////////////////////////////////////////////////////
        // Создать объект
        ///////////////////////////////////////////////////////////////////////
        public SecurityObject CreateObject(IProvider provider, Scope scope, 
            IRand rand, string name, object authenticationData, params object[] parameters)
        {
            // проверить корректность параметра
            if (scope == Scope.Any) throw new ArgumentException(); 

            // удалить последний разделитель
            if (name.EndsWith("\\")) name = name.Substring(0, name.Length - 1); 
            
            // для всех хранилищ верхнего уровня
            foreach (string storeName in provider.EnumerateStores(scope))
            {
                // при совпадении имени 
                if (String.Compare(name, storeName, true) == 0) 
                {
                    // открыть хранилище
                    using (SecurityStore store = provider.OpenStore(scope, storeName))
                    {  
                        // указать тип аутентификации
                        store.Authentications = GetAuthentications(store); 
                        
                        // вернуть хранилище
                        return RefObject.AddRef(store); 
                    }
                }
                // проверить наличие имени в пути
                else if (name.ToLower().StartsWith(storeName.ToLower() + "\\"))
                { 
                    // удалить начальную часть
                    name = name.Substring(storeName.Length + 1); 

                    // открыть хранилище
                    using (SecurityStore store = provider.OpenStore(scope, storeName))
                    {
                        // указать тип аутентификации
                        store.Authentications = GetAuthentications(store);

                        // создать объект
                        return CreateObject(store, rand, name, authenticationData, parameters); 
                    }
                }
            }
            // при ошибке выбросить исключение
            throw new NotFoundException(); 
        }
        public SecurityObject CreateObject(SecurityStore store, IRand rand, 
            string name, object authenticationData, params object[] parameters)
        {
            // выполнить разбор имени
            string[] path = store.ParseObjectName(name); if (path.Length == 1)
            {
                // указать генератор случайных данных
                using (IRand rebindRand = RebindRand(rand))
                { 
                    // создать объект
                    return store.CreateObject(rand, path[0], authenticationData, parameters);
                }
            }
            // открыть хранилище
            else using (SecurityObject obj = store.OpenObject(path[0], FileAccess.ReadWrite))
            { 
                // проверить тип объекта
                if (!(obj is SecurityStore)) throw new NotFoundException(); 

                // указать тип аутентификации
                obj.Authentications = GetAuthentications(obj);

                // создать объект 
                return CreateObject((SecurityStore)obj, rand, path[1], authenticationData, parameters); 
            }
        }
        ///////////////////////////////////////////////////////////////////////
        // Открыть объект
        ///////////////////////////////////////////////////////////////////////
        public SecurityObject OpenObject(IProvider provider, Scope scope, string name, FileAccess access)
        {
            // проверить корректность параметра
            if (scope == Scope.Any) throw new ArgumentException(); 

            // удалить последний разделитель
            if (name.EndsWith("\\")) name = name.Substring(0, name.Length - 1); 

            // для всех хранилищ верхнего уровня
            foreach (string storeName in provider.EnumerateStores(scope))
            {
                // при совпадении имени 
                if (String.Compare(name, storeName, true) == 0) 
                {
                    // открыть хранилище
                    using (SecurityStore store = provider.OpenStore(scope, storeName))
                    {  
                        // указать тип аутентификации
                        store.Authentications = GetAuthentications(store); 

                        // вернуть хранилище
                        return RefObject.AddRef(store); 
                    }
                }
                // проверить наличие имени в пути
                else if (name.ToLower().StartsWith(storeName.ToLower() + "\\"))
                { 
                    // удалить начальную часть
                    name = name.Substring(storeName.Length + 1); 

                    // открыть хранилище
                    using (SecurityStore store = provider.OpenStore(scope, storeName))
                    {
                        // указать тип аутентификации
                        store.Authentications = GetAuthentications(store);

                        // открыть объект
                        return OpenObject(store, name, access); 
                    }
                }
            }
            // при ошибке выбросить исключение
            throw new NotFoundException(); 
        }
        public SecurityObject OpenObject(SecurityStore store, string name, FileAccess access)
        {
            // выполнить разбор имени
            string[] path = store.ParseObjectName(name); if (path.Length == 1)
            {
                // открыть объект
                using (SecurityObject obj = store.OpenObject(path[0], access))
                {
                    // указать тип аутентификации
                    obj.Authentications = GetAuthentications(obj);

                    // вернуть объект
                    return RefObject.AddRef(obj); 
                }
            }
            // открыть хранилище
            else using (SecurityObject obj = store.OpenObject(path[0], access))
            { 
                // проверить тип объекта
                if (!(obj is SecurityStore)) throw new NotFoundException(); 

                // указать тип аутентификации
                obj.Authentications = GetAuthentications(obj);

                // открыть объект 
                return OpenObject((SecurityStore)obj, path[1], access); 
            }
        }
        ///////////////////////////////////////////////////////////////////////
        // Удалить объект
        ///////////////////////////////////////////////////////////////////////
        public void DeleteObject(IProvider provider, Scope scope, string name)
        {
            // проверить корректность параметра
            if (scope == Scope.Any) throw new ArgumentException(); 

            // удалить последний разделитель
            if (name.EndsWith("\\")) name = name.Substring(0, name.Length - 1); 

            // для всех хранилищ верхнего уровня
            foreach (string storeName in provider.EnumerateStores(scope))
            {
                // при совпадении имени 
                if (String.Compare(name, storeName, true) == 0)
                { 
                    // хранилище верхнего уровня не удаляется
                    throw new InvalidOperationException(); 
                }
                // проверить наличие имени в пути
                if (name.ToLower().StartsWith(storeName.ToLower() + "\\"))
                { 
                    // удалить начальную часть
                    name = name.Substring(storeName.Length + 1); 

                    // открыть хранилище
                    using (SecurityStore store = provider.OpenStore(scope, storeName))
                    {
                        // указать тип аутентификации
                        store.Authentications = GetAuthentications(store);

                        // удалить объект
                        DeleteObject(store, name); return; 
                    }
                }
            }
            // при ошибке выбросить исключение
            throw new NotFoundException(); 
        }
        public void DeleteObject(SecurityStore store, string name)
        {
            // выполнить разбор имени
            string[] path = store.ParseObjectName(name); if (path.Length == 1)
            {
                // список аутентификаций
                Authentication[] authentications = new Authentication[0];
                try { 
                    // открыть объект
                    using (SecurityObject obj = store.OpenObject(path[0], FileAccess.Read))
                    {
                        // получить возможные аутентификации
                        authentications = GetAuthentications(obj); 
                    }
                }
                // обработать возможное исключение
                catch (NotFoundException) { return; }
                
                // удалить объект
                store.DeleteObject(path[0], authentications); 
            }
            // открыть хранилище
            else using (SecurityObject obj = store.OpenObject(path[0], FileAccess.ReadWrite))
            {
                // проверить тип объекта
                if (!(obj is SecurityStore)) throw new NotFoundException(); 

                // указать тип аутентификации
                obj.Authentications = GetAuthentications(obj);

                // удалить объект 
                DeleteObject(((SecurityStore)obj), path[1]); 
            }
        }
        ///////////////////////////////////////////////////////////////////////
		// Сгенерировать пару ключей
		///////////////////////////////////////////////////////////////////////
        public ContainerKeyPair GenerateKeyPair(CryptoProvider provider, SecurityInfo info, 
            IRand rand, IParametersFactory factory, string keyOID, KeyUsage keyUsage, KeyFlags keyFlags)
		{
            // указать существующий контейнер
            using (ClientContainer clientContainer = new ClientContainer(provider, info, this))
            try {
                // сгенерировать пару ключей
                return clientContainer.GenerateKeyPair(rand, factory, keyOID, keyUsage, keyFlags); 
            }
            // при отсутствии контейнера
            catch { Container container = null; 

                // открыть хранилище
                using (SecurityStore store = (SecurityStore)OpenObject(provider, info.Scope, info.Store, FileAccess.ReadWrite))
                {
                    // получить типы аутентификации дочерних объектов
                    List<Type> authenticationTypes = new List<Type>(store.GetChildAuthenticationTypes(user)); 

                    // указать генератор случайных данных
                    using (IRand rebindRand = RebindRand(rand))
                    { 
                        // при необходимости аутентификации
                        if (authenticationTypes.Count != 0 && !authenticationTypes.Contains(null))
                        {
                            // отобразить диалог создания контейнера
                            container = (Container)ShowCreate(provider, info, rebindRand, authenticationTypes, keyOID); 
                        }
                        // создать объект без аутентификации
                        else container = (Container)store.CreateObject(rebindRand, info.Name, null, keyOID); 
                        try { 
                            // выбрать параметры алгоритма
                            IParameters keyParameters = factory.GetParameters(rebindRand, keyOID, keyUsage); 

                            // сгенерировать ключи в контейнере
	                        using (KeyPair keyPair = container.GenerateKeyPair(
                                rebindRand, null, keyOID, keyParameters, keyUsage, keyFlags)) 
                            { 
                                // закрыть контейнер
                                return new ContainerKeyPair(info, keyPair.KeyID, keyOID, null);
                            }
                        }
                        // освободить выделенные ресурсы
                        finally { RefObject.Release(container); }
                    }
                }
            }
		}
		///////////////////////////////////////////////////////////////////////
		// Импортировать пару ключей
		///////////////////////////////////////////////////////////////////////
		public ContainerKeyPair ExportKeyPair(CryptoProvider providerFrom, 
            SecurityInfo infoFrom, byte[] keyID, CryptoProvider providerTo, 
            SecurityInfo infoTo, IRand rand, KeyUsage keyUsage, KeyFlags keyFlags)
		{
            // открыть другой контейнер
            using (Container containerFrom = (Container)OpenObject(
                providerFrom, infoFrom.Scope, infoFrom.FullName, FileAccess.Read))
            { 
                // получить открытый ключ
                IPublicKey publicKey = containerFrom.GetPublicKey(keyID);

                // проверить наличие ключа
                if (publicKey == null) throw new NotFoundException();

                // получить сертификат
                Certificate certificate = containerFrom.GetCertificate(keyID);

                // получить личный ключ
                using (IPrivateKey privateKey = containerFrom.GetPrivateKey(keyID))
                {
                    // указать существующий контейнер
                    using (ClientContainer clientContainerTo = new ClientContainer(providerTo, infoTo, this))
                    try { 
                        // импортировать пару ключей
                        return clientContainerTo.ImportKeyPair(rand, publicKey, privateKey, certificate, keyUsage, keyFlags); 
                    }
                    catch { Container containerTo = null; 

                        // открыть хранилище
                        using (SecurityStore storeTo = (SecurityStore)OpenObject(
                            providerTo, infoTo.Scope, infoTo.Store, FileAccess.ReadWrite))
                        { 
                            // получить типы аутентификации дочерних объектов
                            List<Type> authenticationTypes = new List<Type>(storeTo.GetChildAuthenticationTypes(user)); 

                            // указать генератор случайных данных
                            using (IRand rebindRand = RebindRand(rand))
                            { 
                                // при наличии аутентификации
                                if (authenticationTypes.Count != 0 && !authenticationTypes.Contains(null))
                                {
                                    // отобразить диалог создания контейнера
                                    containerTo = (Container)ShowCreate(providerTo, infoTo, rebindRand, authenticationTypes, publicKey.KeyOID); 
                                }
                                // создать объект без аутентификации
                                else containerTo = (Container)storeTo.CreateObject(rebindRand, infoTo.Name, null, publicKey.KeyOID); 
                                try { 
	                                // импортировать ключи в контейнер
			                        using (KeyPair keyPair = containerTo.ImportKeyPair(rebindRand, publicKey, privateKey, keyUsage, keyFlags)) 
                                    { 
                                        // записать сертификат в контейнер
                                        if (certificate != null) containerTo.SetCertificate(keyPair.KeyID, certificate);

                                        // вернуть описание пары ключей контейнера
                                        return new ContainerKeyPair(infoTo, keyPair.KeyID, publicKey.KeyOID, certificate); 
                                    }
                                }
                                // освободить выделенные ресурсы
                                finally { RefObject.Release(containerTo); }
                            }
                        }
                    }
                }
            }
        }
        ///////////////////////////////////////////////////////////////////////
		// Открыть или создать контейнер (только для тестовых целей)
		///////////////////////////////////////////////////////////////////////
        public Container OpenOrCreate(CryptoProvider provider, SecurityInfo info, params object[] parameters)
        {
            // открыть хранилище
            using (SecurityStore store = (SecurityStore)OpenObject(
                provider, info.Scope, info.Store, FileAccess.ReadWrite))
            { 
                try { 
                    // открыть контейнер
                    using (SecurityObject container = store.OpenObject(info.Name, FileAccess.ReadWrite))
                    { 
                        // указать способ аутентификации
                        container.Authentications = GetAuthentications(container); 

                        // вернуть объект
                        return (Container)RefObject.AddRef(container); 
                    }
                }
                // при возникновении ошибки
                catch (NotFoundException) 
                { 
                    // получить типы аутентификации дочерних объектов
                    List<Type> authenticationTypes = new List<Type>(store.GetChildAuthenticationTypes(user)); 

                    // создать генератор случайных данных
                    using (IRand rand = CreateRand(provider, store))
                    { 
                        // при наличии аутентификации
                        if (authenticationTypes.Count != 0 && !authenticationTypes.Contains(null))
                        {
                            // отобразить диалог создания контейнера
                            return (Container)ShowCreate(provider, info, rand, authenticationTypes, parameters);
                        }
                        // создать объект без аутентификации
                        else return (Container)store.CreateObject(rand, info.Name, null, parameters); 
                    }
                }
                // при возникновении ошибки
                catch (Exception e) { string message = e.Message; throw; }  
            }
        }
		public virtual SecurityObject ShowCreate(CryptoProvider provider, SecurityInfo info, 
            IRand rand, List<Type> authenticationTypes, params object[] parameters) 
        { 
            throw new NotSupportedException(); 
        }
        ///////////////////////////////////////////////////////////////////////
		// Генератор случайных данных
		///////////////////////////////////////////////////////////////////////
        public virtual IRand CreateRand(CryptoProvider provider, SecurityObject container)
        {
		    // создать генератор случайных данных
            return provider.CreateRand(container, null); 
        }
        // указать другое графическое окружение
        public virtual IRand RebindRand(IRand rand) { return RefObject.AddRef(rand); }
    }
}
