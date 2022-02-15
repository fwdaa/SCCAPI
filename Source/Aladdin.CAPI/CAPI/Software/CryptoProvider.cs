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
		// фабрика алгоритмов, тип контейнеров и расширения файлов
        private Factories factories; private string type; private string[] extensions; 
        
		// конструктор
		public CryptoProvider(Factories factories, string type, string[] extensions)
        {
            // сохранить фабрики алгоритмов
            this.factories = RefObject.AddRef(factories); this.type = type; this.extensions = extensions; 
        }
		// конструктор
		public CryptoProvider(IEnumerable<Factory> factories, string type, string[] extensions)
        {
            // сохранить фабрики алгоритмов
            this.factories = new Factories(factories); this.type = type; this.extensions = extensions; 
        }
        // освободить выделенные ресурсы
        protected override void OnDispose() { RefObject.Release(factories); base.OnDispose(); }

        // имя провайдера
        public override string Name 
        { 
            // имя провайдера
            get { return String.Format("{0} Cryptographic Provider", type); }
        }
        // используемые расширения
        public string[] Extensions { get { return extensions; }}

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
	    // Управление контейнерами в памяти
	    ///////////////////////////////////////////////////////////////////////
		public Container CreateMemoryContainer(IRand rand, 
            MemoryStream stream, string password, string keyOID)
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
		public byte[][] EnumerateDirectoryContainers(string directory, KeyUsage keyUsage)
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
			            // проверить указание способа использования
			            if (keyUsage == KeyUsage.None) containers.Add(content); 
                            
			            // для всех ключевых наборов
                        else foreach (byte[] keyID in container.GetKeyIDs())
			            {
				            // получить сертификат контейнера
				            Certificate certificate = container.GetCertificate(keyID);
	 
				            // проверить наличие сертификата
				            if (certificate == null) continue; 
                            
			                // проверить область действия сертификата
			                if ((certificate.KeyUsage & keyUsage) == KeyUsage.None) continue; 

                            // добавить содержимое контейнера в список
                            containers.Add(content); break; 
                        }
                    }
	            }
                // вернуть список контейнеров
		        catch {} return containers.ToArray(); 
            }
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
	    public override SecretKeyFactory[] SecretKeyFactories() 
        {
            // указать фильтр программных фабрик
            FactoryFilter filter = new FactoryFilter.Software(null); 
        
            // вернуть поддерживаемые ключи
            return factories.SecretKeyFactories(filter); 
        }
        // поддерживаемые ключи
	    public override KeyFactory[] KeyFactories() 
        {
            // указать фильтр программных фабрик
            FactoryFilter filter = new FactoryFilter.Software(null); 
        
            // вернуть поддерживаемые ключи
            return factories.KeyFactories(filter); 
        }
        // получить алгоритмы по умолчанию
        public override Culture GetCulture(SecurityStore scope, string keyOID) 
        {
            // указать фильтр программных фабрик
            FactoryFilter filter = new FactoryFilter.Software(null); 
        
            // получить алгоритмы по умолчанию
            return factories.GetCulture(scope, filter, keyOID); 
        }
        // получить алгоритмы по умолчанию
        public override PBE.PBECulture GetCulture(PBE.PBEParameters parameters, string keyOID) 
        {
            // получить алгоритмы по умолчанию
            return factories.GetCulture(parameters, keyOID); 
        }
		// создать алгоритм генерации ключей
		protected internal override CAPI.KeyPairGenerator CreateAggregatedGenerator(
            Factory outer, SecurityObject scope, 
            string keyOID, IParameters parameters, IRand rand)
		{
            // указать фильтр программных фабрик
            FactoryFilter filter = new FactoryFilter.Software(null); 

			// создать программный алгоритм генерации ключей
			return factories.CreateAggregatedGenerator(
                outer, scope, filter, keyOID, parameters, rand
            ); 
		}
		// cоздать алгоритм для параметров
		protected internal override IAlgorithm CreateAggregatedAlgorithm(
            Factory outer, SecurityStore scope, 
            ASN1.ISO.AlgorithmIdentifier parameters, Type type)
		{
            // указать фильтр программных фабрик
            FactoryFilter filter = new FactoryFilter.Software(null); 

			// cоздать программный алгоритм для параметров
			return factories.CreateAggregatedAlgorithm(outer, scope, filter, parameters, type); 
		}
	}
}

