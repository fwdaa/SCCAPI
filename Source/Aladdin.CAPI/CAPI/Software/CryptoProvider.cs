using System;
using System.IO;
using System.Reflection;
using System.Collections.Generic;

namespace Aladdin.CAPI.Software
{
	///////////////////////////////////////////////////////////////////////////
	// Провайдер программных алгоритмов
	///////////////////////////////////////////////////////////////////////////
	public abstract class CryptoProvider : CAPI.CryptoProvider
	{
		// фабрика алгоритмов и фабрика генераторов 
        private Factories factories; private IRandFactory randFactory; 
        
        // тип контейнеров и расширения файлов
        private string type; private string[] extensions; 
        
		// конструктор
		public CryptoProvider(IEnumerable<Factory> factories, 
            IRandFactory randFactory, string type, string[] extensions)
        {
            // сохранить фабрики алгоритмов
            this.factories = new Factories(true, factories); 

            // сохранить фабрику генераторов
            this.randFactory = RefObject.AddRef(randFactory); 

            // сохранить переданные параметры
            this.type = type; this.extensions = extensions; 
        }
        // освободить выделенные ресурсы
        protected override void OnDispose() 
        { 
            // освободить выделенные ресурсы
            RefObject.Release(randFactory); factories.Dispose(); base.OnDispose(); 
        }
        // имя провайдера
        public override string Name 
        { 
            // имя провайдера
            get { return String.Format("{0} Cryptographic Provider", type); }
        }
        // обобщенная фабрика алгоритмов
        public Factory Factory { get { return factories; }}

        // используемые расширения
        public string[] Extensions { get { return extensions; }}

        ///////////////////////////////////////////////////////////////////////
        // Генерация случайных данных
        ///////////////////////////////////////////////////////////////////////
    
        // создать генератор случайных данных
        public override IRand CreateRand(object window)
        { 
            // создать генератор случайных данных
            return randFactory.CreateRand(window); 
        } 
		///////////////////////////////////////////////////////////////////////
		// Управление хранилищами провайдера
		///////////////////////////////////////////////////////////////////////
        public override string[] EnumerateStores(Scope scope)
		{
            // проверить корректность параметра
            if (scope != Scope.System && scope != Scope.User) throw new ArgumentException(); 

            // создать список хранилищ
            List<String> stores = new List<String>(); 

            // проверить поддержку XML-конфигурации
            bool supportConfig = IsSupportConfig(scope); 

            // добавить файловое хранилище
            if (supportConfig || IsSupportRegistryDirectories(scope)) stores.Add("FILE"); 

            // при поддержке реестра
            if (IsSupportRegistryStore())
            { 
                // добавить реестр
                if (scope == Scope.System) stores.Add("HKLM"); 
                if (scope == Scope.User  ) stores.Add("HKCU"); 
            }
            // при поддержке XML-конфигурации
            if (supportConfig)
            { 
                // добавить файл конфигурации
                if (scope == Scope.System) stores.Add("FSLM"); 
                if (scope == Scope.User  ) stores.Add("FSCU"); 
            }
            // добавить хранилище в памяти
            stores.Add("MEMORY"); return stores.ToArray(); 
		}
		public override SecurityStore OpenStore(Scope scope, string storeName)
		{
            // преобразовать имя в верхний регистр
            storeName = storeName.ToUpper(); 

            // вернуть хранилище в памяти
            if (storeName == "MEMORY") return new MemoryStore(this); 

            // для файлового хранилища
            else if (storeName == "FILE")
            {
                // при поддержке каталогов в реестре
                if (IsSupportRegistryDirectories(scope)) 
                {
                    // создать источник каталогов
                    IDirectoriesSource source = CreateRegistryDirectories(scope); 

                    // вернуть хранилище контейнеров
                    return new DirectoriesStore(this, scope, source, extensions); 
                }
                else { 
                    // проверить поддержку XML-конфигурации
                    if (!IsSupportConfig(scope)) throw new NotSupportedException(); 

                    // создать источник каталогов
                    IDirectoriesSource source = CreateConfigDirectories(scope); 

                    // вернуть хранилище контейнеров
                    return new DirectoriesStore(this, scope, source, extensions); 
                }
            }
            // для хранилища в реестре
            else if ((scope == Scope.System && storeName == "HKLM") || 
                     (scope == Scope.User   && storeName == "HKCU"))
            {
                // проверить поддержку реестра
                if (!IsSupportRegistryStore()) throw new NotSupportedException(); 

                // вернуть хранилище контейнеров
                return CreateRegistryStore(scope);
            }
            // для хранилища в файле конфигурации 
            else if ((scope == Scope.System && storeName == "FSLM") || 
                     (scope == Scope.User   && storeName == "FSCU"))
            {
                // проверить поддержку XML-конфигурации
                if (!IsSupportConfig(scope)) throw new NotSupportedException(); 

                // вернуть хранилище контейнеров
                return CreateConfigStore(scope);
            }
            // при ошибке выбросить исключение
            throw new ArgumentException(); 
		}
	    ///////////////////////////////////////////////////////////////////////
	    // Поддержка рееестра
	    ///////////////////////////////////////////////////////////////////////
        private bool IsSupportRegistryStore()
        {
            // найти класс
            return Type.GetType("Aladdin.CAPI.Software.RegistryStore", false) != null; 
        }
        private SecurityStore CreateRegistryStore(Scope scope)
        {
            // найти класс
            Type storeType = Type.GetType("Aladdin.CAPI.Software.RegistryStore"); 

            // найти описание конструктора
            ConstructorInfo constructor = storeType.GetConstructor(new Type[] { 
                typeof(CryptoProvider), typeof(Scope), typeof(String)
            }); 
            try { 
                // указать имя раздела реестра
                string registryKey = String.Format("SOFTWARE\\Aladdin\\CAPI\\{0}", type); 

                // указать аргументы конструктора
                object[] args = new object[] { this, scope, registryKey }; 

                // вызвать конструктор
                return (SecurityStore)constructor.Invoke(args); 
            }
            // обработать возможное исключение
            catch (TargetInvocationException e) { throw e.InnerException; }
        }
        private bool IsSupportRegistryDirectories(Scope scope)
        {
            // найти класс
            Type dirType = Type.GetType("Aladdin.CAPI.Software.RegistryDirectories", false); 

            // проверить наличие класса
            if (dirType == null) return false; 

            // создать источник каталогов
            IDirectoriesSource source = CreateRegistryDirectories(scope); 
            try {  
                // найти требуемый метод
                MethodInfo method = source.GetType().GetMethod("HasRedirect"); 

                // проверить отсутствие перенаправления
                return (method == null || !(bool)method.Invoke(source, null)); 
            }
            catch { return false; }
        }
        private IDirectoriesSource CreateRegistryDirectories(Scope scope)
        {
            // найти класс
            Type dirType = Type.GetType("Aladdin.CAPI.Software.RegistryDirectories"); 

            // найти описание конструктора
            ConstructorInfo constructor = dirType.GetConstructor(
                new Type[] { typeof(Scope), typeof(String) }
            ); 
            try { 
                // указать имя раздела реестра
                string registryKey = String.Format("SOFTWARE\\Aladdin\\CAPI\\{0}\\Directories", type); 

                // указать аргументы конструктора
                object[] args = new object[] { scope, registryKey }; 

                // вызвать конструктор
                return (IDirectoriesSource)constructor.Invoke(args); 
            }
            // обработать возможное исключение
            catch (TargetInvocationException e) { throw e.InnerException; }
        }
	    ///////////////////////////////////////////////////////////////////////
	    // Поддержка XML-конфигурации
	    ///////////////////////////////////////////////////////////////////////
        private bool IsSupportConfig(Scope scope)
        {
            // указать тип каталога
            Environment.SpecialFolder type = (scope == Scope.System) ? 
                Environment.SpecialFolder.CommonApplicationData : 
                Environment.SpecialFolder.ApplicationData; 

            // получить профиль пользователя
            string root = Environment.GetFolderPath(type); 

            // указать путь к каталогу
            string directory = String.Format("{0}{1}{2}", 
                root, Path.DirectorySeparatorChar, "Aladdin"
            ); 
            // при отсутствии каталога
            if (!Directory.Exists(directory))
            {
                // создать каталог
                try { Directory.CreateDirectory(directory); } catch { return false; }
            }
            // указать путь к каталогу
            directory = String.Format("{0}{1}{2}", 
                directory, Path.DirectorySeparatorChar, "CAPI"
            ); 
            // при отсутствии каталога
            if (!Directory.Exists(directory))
            {
                // создать каталог
                try { Directory.CreateDirectory(directory); } catch { return false; }
            }
            return true; 
        }
        private SecurityStore CreateConfigStore(Scope scope)
        {
            // указать имя файла конфигурации
            string configFile = String.Format(
                "Aladdin{0}CAPI{0}{1}.config", Path.DirectorySeparatorChar, type
            ); 
            // вернуть хранилище контейнеров
            return new ConfigStore(this, scope, configFile);
        }
        private IDirectoriesSource CreateConfigDirectories(Scope scope)
        {
            // указать имя файла конфигурации
            string configFile = String.Format(
                "Aladdin{0}CAPI{0}{1}.config", Path.DirectorySeparatorChar, type
            ); 
            // вернуть источник каталогов
            return new ConfigDirectories(scope, configFile); 
        }
	    ///////////////////////////////////////////////////////////////////////
	    // Управление контейнерами
	    ///////////////////////////////////////////////////////////////////////
		public virtual Container CreateContainer(IRand rand, 
            ContainerStore store, ContainerStream stream, 
            string password, string keyOID)
		{
			// операция не поддерживается
			throw new NotSupportedException();
        }
		public virtual Container OpenContainer(
            ContainerStore store, ContainerStream stream)
		{
			// операция не поддерживается
			throw new NotSupportedException();
        }
		///////////////////////////////////////////////////////////////////////
		// Управление алгоритмами
		///////////////////////////////////////////////////////////////////////

        // поддерживаемые ключи
	    public override Dictionary<String, SecretKeyFactory> SecretKeyFactories() 
        { 
            // поддерживаемые ключи
            return factories.SecretKeyFactories(); 
        }
        // поддерживаемые ключи
	    public override Dictionary<String, KeyFactory> KeyFactories() 
        { 
            // поддерживаемые ключи
            return factories.KeyFactories(); 
        }

		// создать алгоритм генерации ключей
		protected internal override CAPI.KeyPairGenerator CreateAggregatedGenerator(
            Factory outer, SecurityObject scope, IRand rand, 
            string keyOID, IParameters parameters)
		{
            // проверить тип хранилища
            if (scope != null && !(scope is ContainerStore)) return null; 

            // создать алгоритм генерации ключей
            return factories.CreateAggregatedGenerator(outer, null, rand, keyOID, parameters); 
		}
		// cоздать алгоритм для параметров
		protected internal override IAlgorithm CreateAggregatedAlgorithm(
            Factory outer, SecurityStore scope, 
            string oid, ASN1.IEncodable parameters, Type type)
		{
            // проверить тип хранилища
            if (scope != null && !(scope is ContainerStore)) return null; 

            // создать алгоритм
            return factories.CreateAggregatedAlgorithm(outer, null, oid, parameters, type); 
        }
	    ///////////////////////////////////////////////////////////////////////
	    // Управление контейнерами в памяти
	    ///////////////////////////////////////////////////////////////////////
		public Container CreateMemoryContainer(IRand rand, 
            MemoryStream stream, string keyOID, string password)
		{
            // открыть хранилище
            using (SecurityStore store = OpenStore(Scope.System, "MEMORY"))
            {
                // создать контейнер
                return (Container)store.CreateObject(rand, stream, password, keyOID); 
            }
        }
		public Container OpenMemoryContainer(
            MemoryStream stream, FileAccess access, string password)
		{
            // открыть хранилище
            using (SecurityStore store = OpenStore(Scope.System, "MEMORY"))
            {
                // открыть контейнер
                using (Container container = (Container)store.OpenObject(stream, access))
                { 
                    // установить пароль
                    if (password != null) container.Password = password; 
                    
                    // вернуть объект контейнера
                    container.AddRef(); return container; 
                }
            }
        }
	    ///////////////////////////////////////////////////////////////////////
	    // Каталоги файловых контейнеров
	    ///////////////////////////////////////////////////////////////////////
		public SecurityStore OpenDirectoryStore(string directory, FileAccess access)
		{
		    // указать файловое хранилище
		    using (SecurityStore store = new DirectoriesStore(
                this, Scope.User, new string[] { directory }, extensions))
            {
                // открыть каталог
                return (SecurityStore)store.OpenObject(directory, access); 
            }
        }
		public byte[][] EnumerateDirectoryContainers(string directory, Predicate<CAPI.Container> filter)
		{
			// создать список сертификатов
			List<Byte[]> containers =  new List<Byte[]>();
 
            // открыть каталог контейнеров
            using (SecurityStore store = OpenDirectoryStore(directory, FileAccess.Read))
            { 
                // для всех контейнеров PKCS12
	            foreach (string file in store.EnumerateObjects())
	            try {
                    // прочитать содержимое контейнера
                    byte[] content = File.ReadAllBytes(file); 

		            // открыть контейнер
		            using (CAPI.Container container = (CAPI.Container)store.OpenObject(file, FileAccess.Read))
		            {
                        // добавить содержимое контейнера в список
                        if (filter(container)) containers.Add(content); 
                    }
	            }
                // вернуть список контейнеров
		        catch {} return containers.ToArray(); 
            }
		}
	}
}

