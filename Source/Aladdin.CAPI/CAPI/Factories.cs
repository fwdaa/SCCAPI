using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis; 

namespace Aladdin.CAPI
{
	///////////////////////////////////////////////////////////////////////////
	// Набор фабрик алгоритмов
	///////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
	public class Factories : Factory, IEnumerable<Factory>
	{
		// фабрики алгоритмов
        private List<Factory> factories; private List<CryptoProvider> providers;

		// конструктор
		public Factories(params Factory[] factories) 
            
            // сохранить переданные параметры
            : this((IEnumerable<Factory>)factories) {}

		// конструктор
		public Factories(IEnumerable<Factory> factories)
		{
			// создать список фабрик
            this.factories = new List<Factory>(); 

            // создать список провайдеров
            this.providers = new List<CryptoProvider>(); 

            // заполнить списки фабрик и провайдеров
            FillFactories(factories); 
		}
        private void FillFactories(IEnumerable<Factory> factories)
        {
            // для всех фабрик алгоритмов
            foreach (Factory factory in factories)
            {
                // для набора фабрик
                if (factory is IEnumerable<Factory>)
                {
                    // перечислить фабрики набора
                    FillFactories((IEnumerable<Factory>)factory);
                }
                else { 
                    // добавить фабрику в список
                    this.factories.Add(RefObject.AddRef(factory)); 

                    // для криптографического провайдера
                    if (factory is CryptoProvider)
                    {
                        // добавить провайдер в список
                        this.providers.Add((CryptoProvider)factory); 
                    }
                }
            }
        }
        // освободить используемые ресурсы
        protected override void OnDispose()
        {
            // для всех фабрик алгоритмов
		    foreach (Factory factory in factories) 
            try { 
                // освободить выделенные ресурсы
                RefObject.Release(factory); 
            }
            // вызвать базовую функцию
            catch {} base.OnDispose();
        }
        ///////////////////////////////////////////////////////////////////////
        // Свойства набора фабрик
        ///////////////////////////////////////////////////////////////////////
        
        // криптографические провайдеры
        public List<CryptoProvider> Providers { get { return providers; }} 

        // группы провайдеров
        public List<CryptoProvider> ProviderGroups { get 
        { 
            // создать список провайдеров
            List<CryptoProvider> providers = new List<CryptoProvider>(); 

            // создать список групп
            List<String> groups = new List<String>(); 

            // для всех провайдеров
            foreach (CryptoProvider provider in this.providers)
            {
                // проверить отсутствие группы
                if (groups.Contains(provider.Group)) continue; 

                // добавить провайдер
                providers.Add(provider); groups.Add(provider.Group); 
            }
            return providers; 
        }} 
        // перечислитель внутренних фабрик
		public IEnumerator<Factory> GetEnumerator() 
		{ 
			// перечислитель внутренних фабрик
			return factories.GetEnumerator(); 
		}
		// перечислитель внутренних фабрик
		IEnumerator IEnumerable.GetEnumerator() { return factories.GetEnumerator(); }

		// получить элемент коллекции
		public Factory this[int i] { get { return factories[i]; } }

		// размер коллекции
		public int Length { get { return factories.Count; } }

        ///////////////////////////////////////////////////////////////////////
        // Поддерживаемые ключи
        ///////////////////////////////////////////////////////////////////////
	    public override SecretKeyFactory[] SecretKeyFactories() 
        { 
            // поддерживаемые ключи
            return SecretKeyFactories(null); 
        }
	    public SecretKeyFactory[] SecretKeyFactories(FactoryFilter filter) 
        { 
            // создать список поддерживаемых ключей
            List<SecretKeyFactory> keyFactories = new List<SecretKeyFactory>(); 
        
            // для всех фабрик алгоритмов
            foreach (Factory factory in factories)
            {
                // для допустимой фабрики
                if (filter == null || filter.IsMatch(factory))
                {
                    // добавить поддерживаемые ключи
                    keyFactories.AddRange(factory.SecretKeyFactories()); 
                }
            }
            // вернуть список поддерживаемых ключей
            return keyFactories.ToArray(); 
        }
	    public override KeyFactory[] KeyFactories() 
        { 
            // поддерживаемые ключи
            return KeyFactories(null); 
        }
	    public KeyFactory[] KeyFactories(FactoryFilter filter) 
        { 
            // создать список поддерживаемых ключей
            List<KeyFactory> keyFactories = new List<KeyFactory>(); 
        
            // для всех фабрик алгоритмов
            foreach (Factory factory in factories)
            {
                // для допустимой фабрики
                if (filter == null || filter.IsMatch(factory))
                {
                    // добавить поддерживаемые ключи
                    keyFactories.AddRange(factory.KeyFactories()); 
                }
            }
            // вернуть список поддерживаемых ключей
            return keyFactories.ToArray(); 
        }
	    ///////////////////////////////////////////////////////////////////////
        // Используемые алгоритмы по умолчанию
	    ///////////////////////////////////////////////////////////////////////
        public override Culture GetCulture(SecurityStore scope, string keyOID) 
        {
            // получить алгоритмы по умолчанию
            return GetCulture(scope, null, keyOID); 
        }
        public Culture GetCulture(SecurityStore scope, FactoryFilter filter, string keyOID) 
        {
            if (scope == null || scope is Software.ContainerStore)
            {
                // указать фильтр программных фабрик
                FactoryFilter softwareFilter = new FactoryFilter.Software(filter);

                // для всех фабрик алгоритмов
                foreach (Factory factory in factories)
                {
                    // для допустимой фабрики
                    if (softwareFilter.IsMatch(factory))
                    {
                        // получить алгоритмы по умолчанию
                        Culture culture = factory.GetCulture(scope, keyOID); 
                
                        // проверить наличие алгоритмов
                        if (culture != null) return culture; 
                    }
                }
            }
            else {
                // указать фильтр провайдеров
                FactoryFilter providerFilter = new FactoryFilter.Provider(filter);

                // для всех фабрик алгоритмов
                foreach (Factory factory in factories)
                {
                    // для допустимой фабрики
                    if (providerFilter.IsMatch(factory))
                    {
                        // получить алгоритмы по умолчанию
                        Culture culture = factory.GetCulture(scope, keyOID); 
                
                        // проверить наличие алгоритмов
                        if (culture != null) return culture; 
                    }
                }
            }
            return null; 
        }
	    ///////////////////////////////////////////////////////////////////////
        // Используемые алгоритмы по умолчанию
	    ///////////////////////////////////////////////////////////////////////
        public override PBE.PBECulture GetCulture(PBE.PBEParameters parameters, string keyOID) 
        {
            // для всех фабрик алгоритмов
            foreach (Factory factory in factories)
            {
                // получить алгоритмы по умолчанию
                PBE.PBECulture culture = factory.GetCulture(parameters, keyOID); 

                // проверить наличие алгоритмов
                if (culture != null) return culture; 
            }
            return null; 
        }
        ///////////////////////////////////////////////////////////////////////
        // Создать алгоритм генерации ключей
        ///////////////////////////////////////////////////////////////////////
        protected internal override KeyPairGenerator CreateAggregatedGenerator(
            Factory outer, SecurityObject scope, 
            string keyOID, IParameters parameters, IRand rand)
		{
            // создать алгоритм генерации ключей
            return CreateAggregatedGenerator(outer, scope, null, keyOID, parameters, rand); 
		}
        protected internal KeyPairGenerator CreateAggregatedGenerator(
            Factory outer, SecurityObject scope, FactoryFilter filter, 
            string keyOID, IParameters parameters, IRand rand)
        {
            // для программных алгоритмов
            if (scope == null || scope is Software.Container)
            {
                // указать фильтр программных фабрик
                FactoryFilter softwareFilter = new FactoryFilter.Software(filter);

                // для всех фабрик алгоритмов
                foreach (Factory factory in factories)
                {
                    // для допустимой фабрики
                    if (softwareFilter.IsMatch(factory))
                    {
                        // создать алгоритм генерации ключей
                        KeyPairGenerator generator = factory.CreateAggregatedGenerator(
                            outer, scope, keyOID, parameters, rand
                        );
                        // проверить наличие алгоритма
                        if (generator != null) return generator;
                    }
                }
            }
            // указать фильтр провайдеров
            FactoryFilter providerFilter = new FactoryFilter.Provider(filter);

            // для всех фабрик алгоритмов
            foreach (Factory factory in factories)
            {
                // для допустимой фабрики
                if (providerFilter.IsMatch(factory))
                {
                    // создать алгоритм генерации ключей
                    KeyPairGenerator generator = factory.CreateAggregatedGenerator(
                        outer, scope, keyOID, parameters, rand
                    );
                    // проверить наличие алгоритма
                    if (generator != null) return generator;
                }
            }
            return null; 
        }
        ///////////////////////////////////////////////////////////////////////
        // Создать алгоритм
        ///////////////////////////////////////////////////////////////////////
        protected internal override IAlgorithm CreateAggregatedAlgorithm(
            Factory outer, SecurityStore scope, 
            ASN1.ISO.AlgorithmIdentifier parameters, Type type)
		{
            // создать алгоритм
            return CreateAggregatedAlgorithm(outer, scope, null, parameters, type); 
		}
        protected internal IAlgorithm CreateAggregatedAlgorithm(
            Factory outer, SecurityStore scope, FactoryFilter filter,
            ASN1.ISO.AlgorithmIdentifier parameters, Type type)
        {
            // для программных алгоритмов
            if (scope == null || scope is Software.ContainerStore)
            {
                // указать фильтр программных фабрик
                FactoryFilter softwareFilter = new FactoryFilter.Software(filter);

                // для всех фабрик алгоритмов
                foreach (Factory factory in factories)
                {
                    // для допустимой фабрики
                    if (softwareFilter.IsMatch(factory))
                    {
                        // создать алгоритм
                        IAlgorithm algorithm = factory.CreateAggregatedAlgorithm(
                            outer, scope, parameters, type
                        );
                        // проверить наличие алгоритма
                        if (algorithm != null) return algorithm;
                    }
                }
            }
            // указать фильтр провайдеров
            FactoryFilter providerFilter = new FactoryFilter.Provider(filter);

            // для всех фабрик алгоритмов
            foreach (Factory factory in factories)
            {
                // для допустимой фабрики
                if (providerFilter.IsMatch(factory))
                {
                    // создать алгоритм
                    IAlgorithm algorithm = factory.CreateAggregatedAlgorithm(
                        outer, scope, parameters, type
                    );
                    // проверить наличие алгоритма
                    if (algorithm != null) return algorithm;
                }
            }
            return null;
        }
    }
}
