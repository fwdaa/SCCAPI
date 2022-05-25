using System;
using System.IO;
using System.Xml;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.Serialization;
using System.Diagnostics.CodeAnalysis; 

namespace Aladdin.CAPI
{
	///////////////////////////////////////////////////////////////////////////
	// Криптографическая среда
	///////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
    [Serializable]
	public sealed class CryptoEnvironment : ExecutionContext, 
        IDeserializationCallback, IParametersFactory, ICultureFactory
	{
        // секция конфигурации
        private Environment.ConfigSection section; 

        // фабрики алгоритмов и криптопровайдеры
		[NonSerialized] private Factories            factories; 
        [NonSerialized] private List<CryptoProvider> providers; 
        
        // фабрики генераторов случайных данных
        [NonSerialized] private List<IRandFactory> randFactories; 
        [NonSerialized] private bool hardwareRand; 
        
        // расширения по именам 
        [NonSerialized] private Dictionary<String, GuiPlugin> plugins;

        // отображения по идентификаторам ключей
        [NonSerialized] private Dictionary<String, String > keyNames;    // имена ключей
        [NonSerialized] private Dictionary<String, String > keyPlugins;  // имена расширений
        [NonSerialized] private Dictionary<String, Culture> keyCultures; // параметры алгоритмов

        // конструктор
		public CryptoEnvironment(string file) 

			// прочитать среду из файла
			: this(Environment.ConfigSection.FromFile(file)) {} 
		
        // конструктор
		public CryptoEnvironment(Stream stream) 

			// прочитать среду из файла
			: this(Environment.ConfigSection.FromStream(stream)) {} 

        // конструктор
		public CryptoEnvironment(XmlDocument document) 

			// прочитать среду из документа
			: this(new Environment.ConfigSection(document)) {} 

        // конструктор
        public CryptoEnvironment(Environment.ConfigSection section)
		{
            // инициализировать данные
            this.section = section; OnDeserialization(this); 
        }
        // инициализировать данные 
        public void OnDeserialization(object sender)
        {
            // инициализировать переменные
            plugins     = new Dictionary<String, GuiPlugin>();
            keyNames    = new Dictionary<String, String   >();
            keyPlugins  = new Dictionary<String, String   >();
		    keyCultures = new Dictionary<String, Culture  >();

            // получить параметры сборки
            AssemblyName assemblyName = Assembly.GetExecutingAssembly().GetName(); 

            // получить токен сборки
            string assemblyToken = Arrays.ToHexString(assemblyName.GetPublicKeyToken()); 

            // указать идентификацию сборки
            string identityString = String.Format(
                ", Version={0}, Culture=neutral, PublicKeyToken={1}", 
                assemblyName.Version, assemblyToken.ToLower()
            ); 
			// создать список фабрик классов
			List<Factory> factories = new List<Factory>(); 
            
			// создать список фабрик генераторов
            randFactories = new List<IRandFactory>(); hardwareRand = false; 

			// для всех фабрик алгоритмов
			foreach (Environment.ConfigFactory element in section.Factories)
			try {
                // определить класс фабрики
                string className = element.Class + identityString; 

                // добавить фабрику классов
                factories.Add((Factory)LoadObject(className)); 
            }
            catch {}

            // объединить фабрики алгоритмов
            try { this.factories = new Factories(false, factories.ToArray()); }
            finally { 
                // освободить выделенные ресурсы
                foreach (Factory factory in factories) RefObject.Release(factory);
            }
			// для генераторов случайных данных
			foreach (Environment.ConfigRandFactory element in section.Rands)
			try {
                // создать фабрику генераторов
                if (element.GUI) randFactories.Add(new GuiRandFactory(element, identityString)); 
                else { 
                    // определить класс генератора
                    string className = element.Class + identityString; 

                    // создать фабрику генераторов
                    randFactories.Add((IRandFactory)LoadObject(className)); hardwareRand = true; 
                }
            }
            catch {}

			// для всех типов криптографических культур
			foreach (Environment.ConfigPlugin element in section.Plugins)
            try { 
                // создать расширение
                GuiPlugin plugin = new GuiPlugin(element, identityString); 

                // сохранить расширение
                plugins.Add(element.Name, plugin);
            }
            catch {}

			// для всех допустимых ключей
			foreach (Environment.ConfigKey element in section.Keys)
            try {
                // определить класс культуры
                string className = element.Class + identityString; 

                // добавить культуру в список
                keyCultures.Add(element.OID, (Culture)LoadObject(className)); 

                // сохранить имя ключа
                keyNames.Add(element.OID, element.Name); 

                // добавить имя расширения 
                keyPlugins.Add(element.OID, element.Plugin); 
            }
            // создать список криптопровайдеров
            catch {} providers = new List<CryptoProvider>(); 

            // создать провайдер PKCS12 
            CryptoProvider provider = new PKCS12.CryptoProvider(this); 

            // скорректировать счетчик ссылок
            RefObject.Release(this); 

            // заполнить список криптопровайдеров
            providers.Add(provider); providers.AddRange(this.factories.Providers); 
        }
		// загрузить объект
		private object LoadObject(string className, params object[] args)
		{
			// указать режим поиска конструктора
			BindingFlags flags = BindingFlags.Instance | 
				BindingFlags.Public | BindingFlags.CreateInstance; 

			// получить описание типа
			Type type = Type.GetType(className, true); 

            // создать список типов аргументов
            Type[] argTypes = new Type[args.Length]; 

            // заполнить список типов аргументов
            for (int i = 0; i < args.Length; i++) argTypes[i] = args[i].GetType(); 

			// получить описание конструктора
			ConstructorInfo constructor = type.GetConstructor(
				flags, null, argTypes, null
			); 
			// проверить наличие конструктора
			if (constructor == null) throw new TargetException();

			// загрузить объект
			try { return constructor.Invoke(args); }

            // обработать исключение
            catch (TargetInvocationException e) { throw e.InnerException; }
		}
        // освободить используемые ресурсы
        protected override void OnDispose()
        {
            // для всех плагинов
            foreach (GuiPlugin plugin in plugins.Values)
            {
                // освободить выделенные ресурсы
                plugin.Release(); 
            }
            // для всех фабрик генераторов
            foreach (IRandFactory randFactory in randFactories)
            {
                // освободить выделенные ресурсы
                randFactory.Release(); 
            }
            // освободить выделенные ресурсы
            RefObject.AddRef(this); providers[0].Release(); 
            
            // освободить выделенные ресурсы
            factories.Release(); base.OnDispose(); 
        }
        ///////////////////////////////////////////////////////////////////////
        // Фабрики алгоритмов
        ///////////////////////////////////////////////////////////////////////

        // фабрики алгоритмов
        public override Factories Factories { get { return factories; }}

        // криптопровайдеры
        public IEnumerable<CryptoProvider> Providers { get { return providers; }}

        // получить провайдер PKCS12
        public PKCS12.CryptoProvider GetPKCS12Provider()
        {
            // получить провайдер PKCS12
            return (PKCS12.CryptoProvider)providers[0]; 
        }
        ///////////////////////////////////////////////////////////////////////
        // Параметры и отображаемое имя ключа
        ///////////////////////////////////////////////////////////////////////
        public IParameters GetKeyParameters(IRand rand, string keyOID, KeyUsage keyUsage)
        {
            // определить имя плагина 
            string pluginName = GetKeyPlugin(keyOID); 

            // проверить наличие плагина
            if (!plugins.ContainsKey(pluginName)) throw new NotFoundException();

            // отобразить диалог выбора параметров ключа
            return plugins[pluginName].GetKeyParameters(rand, keyOID, keyUsage);
        }
        public string GetKeyName(string keyOID)
        {
            // отображаемое имя идентификатора
            return keyNames.ContainsKey(keyOID) ? keyNames[keyOID] : keyOID;
        }
        public string GetKeyPlugin(string keyOID)
        {
            // проверить наличие расширения 
            if (!keyPlugins.ContainsKey(keyOID)) throw new NotFoundException();

            // вернуть имя плагина 
            return keyPlugins[keyOID]; 
        }
        ///////////////////////////////////////////////////////////////////////
        // Параметры алгоритмов по умолчанию
        ///////////////////////////////////////////////////////////////////////
        public Culture GetCulture(string keyOID)
        {
            // проверить наличие расширения 
            if (!keyCultures.ContainsKey(keyOID)) throw new NotFoundException();

            // вернуть параметры алгоритмов по умолчанию
            return keyCultures[keyOID]; 
        }
        ///////////////////////////////////////////////////////////////////////
        // Парольная защита для контейнера PKCS12
        ///////////////////////////////////////////////////////////////////////
        public override PBE.PBECulture GetPBECulture(object window, string keyOID)
        {
            // определить имя плагина 
            string pluginName = GetKeyPlugin(keyOID); 

            // проверить наличие плагина
            if (!plugins.ContainsKey(pluginName)) throw new NotFoundException();

            // получить соответствующий плагин
            GuiPlugin plugin = plugins[pluginName]; 

            // отобразить диалог выбора криптографической культуры
            if (window != null) return plugin.GetPBECulture(window, keyOID); 
             
            // вернуть парольную защиту по умолчанию
            return GetCulture(keyOID).PBE(plugin.PBEParameters); 
        }
        ///////////////////////////////////////////////////////////////////////
        // Cоздать генератор случайных данных
        ///////////////////////////////////////////////////////////////////////
        public override IRand CreateRand(object window)
        {
			// для генераторов случайных данных
			foreach (IRandFactory randFactory in randFactories)
			{
                // проверить допустимость фабрики
                if (window == null && randFactory is GuiRandFactory) continue; 

                // создать генератор
                IRand rand = randFactory.CreateRand(window); 
                
                // проверить создание генератора
                if (rand != null) return rand; 
            } 
            // для всех фабрик алгоритмов
            foreach (Factory factory in factories)
            {
                // проверить наличие провайдера
                if (!(factory is CryptoProvider)) continue; 

                // преобразовать тип фабрики
                CryptoProvider provider = (CryptoProvider)factory;
                try { 
                    // создать генератор случайных данных
                    IRand rand = provider.CreateRand(window); 

                    // проверить наличие алгоритма
                    if (rand != null) return rand;
                }
                catch {}
            }
            // создать генератор случайных данных
            return new Rand(window); 
        }
        // признак наличия аппаратного генератора
        public bool IsHardwareRand() { return hardwareRand; }
	}
}
