using System;
using System.Collections.Generic;
using System.Reflection;

namespace Aladdin.CAPI
{
	///////////////////////////////////////////////////////////////////////////
	// Криптографическая среда
	///////////////////////////////////////////////////////////////////////////
	public class CryptoEnvironment : ExecutionContext
	{
        // фабрики алгоритмов и генераторов случайных данных
		private Factories factories; private List<ConfigRandFactory> randFactories; 
        
        // отображаемые имена ключей
        private Dictionary<String, String> names;

        // отображение идентификаторов ключей на имена расширений
        private Dictionary<String, String> mappings; 

        // расширения криптографических культур
        private Dictionary<String, CulturePlugin> plugins;

        // конструктор
		public CryptoEnvironment(string file) 

			// прочитать среду из файла
			: this(Environment.ConfigSection.FromFile(file)) {} 
		
        // конструктор
        public CryptoEnvironment(Environment.ConfigSection section)
		{
            // инициализировать переменные
		    names      = new Dictionary<String, String       >();
            mappings   = new Dictionary<String, String       >();
            plugins    = new Dictionary<String, CulturePlugin>();

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
            randFactories = new List<ConfigRandFactory>(); 

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
			foreach (Environment.ConfigRand element in section.Rands)
			try {
                // определить класс генератора
                string className = element.Class + identityString; 

                // создать фабрику генераторов
                using (IRandFactory randFactory = (IRandFactory)LoadObject(className))
                { 
                    // создать фабрику генераторов
                    randFactories.Add(new ConfigRandFactory(randFactory, element.Critical)); 
                }
            }
            catch {}

			// для всех типов криптографических культур
			foreach (Environment.ConfigPlugin element in section.Plugins)
            try { 
                // определить класс фабрики
                string className = element.Class + identityString; 

                // прочитать параметры шифрования по паролю
                PBE.PBEParameters pbeParameters = new PBE.PBEParameters(
                    element.PBMSaltLength, element.PBMIterations,  
                    element.PBESaltLength, element.PBEIterations 
                ); 
                // загрузить расширение
                CulturePlugin plugin = (CulturePlugin)LoadObject(className, pbeParameters); 

                // сохранить расширение
                plugins.Add(element.Name, plugin);
            }
            catch {}

			// для всех допустимых ключей
			foreach (Environment.ConfigKey element in section.Keys)
            try {
                // проверить наличие описания семейства
                if (!plugins.ContainsKey(element.Plugin)) throw new NotFoundException();
                
                // добавить отображаемое имя
                names.Add(element.OID, element.Name); 

                // добавить отображение имени
                mappings.Add(element.OID, element.Plugin); 
            }
            catch {}
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
            foreach (CulturePlugin plugin in plugins.Values)
            {
                // освободить выделенные ресурсы
                plugin.Release(); 
            }
            // для всех фабрик генераторов
            foreach (ConfigRandFactory randFactory in randFactories)
            {
                // освободить выделенные ресурсы
                randFactory.Release(); 
            }
            // освободить выделенные ресурсы
            factories.Release(); base.OnDispose(); 
        }
        ///////////////////////////////////////////////////////////////////////
        // Фабрики алгоритмов
        ///////////////////////////////////////////////////////////////////////
        public Factories EnumerateFactories() 
        { 
            // создать провайдер PKCS12
            using (CryptoProvider provider = CreatePKCS12Provider())
            { 
                // создать список фабрик
                List<Factory> factories = new List<Factory>(); 

                // заполнить список фабрик
                factories.Add(provider); factories.AddRange(this.factories); 

                // создать обобщенную фабрику
                return new Factories(false, factories.ToArray()); 
            }
        }
        // фабрика алгоритмов
        public Factories Factory { get { return factories; }}

        // создать провайдер PKCS12
        public PKCS12.CryptoProvider CreatePKCS12Provider()
        {
            // создать провайдер PKCS12
            return new PKCS12.CryptoProvider(this, factories); 
        }
        ///////////////////////////////////////////////////////////////////////
        // Параметры и отображаемое имя ключа
        ///////////////////////////////////////////////////////////////////////
        public override IParameters GetParameters(IRand rand, string keyOID, KeyUsage keyUsage)
        {
            // проверить наличие расширения 
            if (!mappings.ContainsKey(keyOID)) throw new NotFoundException();

            // отобразить диалог выбора параметров ключа
            return plugins[mappings[keyOID]].GetParameters(rand, keyOID, keyUsage);
        }
        public String GetKeyName(string keyOID)
        {
            // отображаемое имя идентификатора
            return names.ContainsKey(keyOID) ? names[keyOID] : keyOID;
        }
        ///////////////////////////////////////////////////////////////////////
        // Парольная защита для контейнера PKCS12
        ///////////////////////////////////////////////////////////////////////
        public override PBE.PBECulture GetCulture(object window, string keyOID)
        {
            // проверить наличие расширения 
            if (!mappings.ContainsKey(keyOID)) throw new NotFoundException();

            // получить соответствующий плагин
            CulturePlugin plugin = plugins[mappings[keyOID]]; 

            // отобразить диалог выбора криптографической культуры
            if (window != null) return plugin.GetCulture(window, keyOID); 
             
            // вернуть парольную защиту по умолчанию
            return factories.GetCulture(plugin.PBEParameters, keyOID); 
        }
        ///////////////////////////////////////////////////////////////////////
        // Cоздать генератор случайных данных
        ///////////////////////////////////////////////////////////////////////
        public bool HasHardwareRand() { return randFactories.Count > 0; }
        
        // создать генератор случайных данных
        public override IRand CreateRand(object window)
        {
			// для генераторов случайных данных
			foreach (ConfigRandFactory randFactory in randFactories)
			{
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
	}
}
