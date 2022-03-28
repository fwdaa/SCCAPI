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
		// фабрики алгоритмов и провайдеры алгоритмов
        private List<Factory> factories; private List<CryptoProvider> providers;

		// конструктор
		public Factories(bool software, params Factory[] factories) 
            
            // сохранить переданные параметры
            : this(software, (IEnumerable<Factory>)factories) {}

		// конструктор
		public Factories(bool software, IEnumerable<Factory> factories)
		{
			// создать список фабрик
            this.factories = new List<Factory>(); 

            // создать список провайдеров
            this.providers = new List<CryptoProvider>(); 

            // заполнить списки фабрик и провайдеров
            FillFactories(software, factories); 
		}
        private void FillFactories(bool software, IEnumerable<Factory> factories)
        {
            // для всех фабрик алгоритмов
            foreach (Factory factory in factories)
            {
                // для набора фабрик
                if (factory is IEnumerable<Factory>)
                {
                    // перечислить фабрики набора
                    FillFactories(software, (IEnumerable<Factory>)factory);
                }
                // для криптопровайдера
                else if (factory is CryptoProvider)
                {
                    if (!software)
                    {
                        // добавить фабрику в список
                        this.factories.Add(RefObject.AddRef(factory)); 

                        // добавить провайдер в список
                        this.providers.Add((CryptoProvider)factory); 
                    }
                }
                // добавить фабрику в список
                else this.factories.Add(RefObject.AddRef(factory)); 
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
	    public override KeyFactory[] KeyFactories() 
        { 
            // создать список поддерживаемых ключей
            Dictionary<String, KeyFactory> keyFactories = new Dictionary<String, KeyFactory>(); 
        
            // для всех фабрик алгоритмов
            foreach (Factory factory in factories)
            {
                // для всех фабрик ключей
                foreach (KeyFactory keyFactory in factory.KeyFactories())
                {
                    // при отсутствии фабрики ключей
                    if (!keyFactories.ContainsKey(keyFactory.KeyOID))
                    {
                        // добавить фабрику ключей
                        keyFactories.Add(keyFactory.KeyOID, keyFactory); 
                    }
                }
            }
            // создать список фабрик
            return new List<KeyFactory>(keyFactories.Values).ToArray(); 
        }
        ///////////////////////////////////////////////////////////////////////
        // Создать алгоритм генерации ключей
        ///////////////////////////////////////////////////////////////////////
        protected internal override KeyPairGenerator CreateAggregatedGenerator(
            Factory outer, SecurityObject scope, IRand rand, 
            string keyOID, IParameters parameters)
        {
            if (scope == null) 
            {
                // для всех программных фабрик алгоритмов
                foreach (Factory factory in factories)
                {
                    // проверить тип фабрики
                    if (factory is CryptoProvider) continue; 

                    // создать алгоритм генерации ключей
                    KeyPairGenerator generator = factory.CreateAggregatedGenerator(
                        outer, scope, rand, keyOID, parameters
                    );
                    // проверить наличие алгоритма
                    if (generator != null) return generator;
                }
                // для всех программных провайдеров
                foreach (Factory factory in factories)
                {
                    // проверить тип фабрики
                    if (!(factory is Software.CryptoProvider)) continue; 

                    // создать алгоритм генерации ключей
                    KeyPairGenerator generator = factory.CreateAggregatedGenerator(
                        outer, scope, rand, keyOID, parameters
                    );
                    // проверить наличие алгоритма
                    if (generator != null) return generator;
                }
            }
            // для провайдера алгоритмов
            else if (scope.Provider is CryptoProvider)
            { 
                // выполнить преобразование типа
                CryptoProvider provider = (CryptoProvider)scope.Provider; 

                // создать алгоритм генерации ключей
                KeyPairGenerator generator = provider.CreateAggregatedGenerator(
                    outer, scope, rand, keyOID, parameters
                );
                // проверить наличие алгоритма
                if (generator != null) return generator;
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
            if (scope == null) 
            {
                // для всех программных фабрик алгоритмов
                foreach (Factory factory in factories)
                {
                    // проверить тип фабрики
                    if (factory is CryptoProvider) continue; 
                
                    // создать алгоритм
                    IAlgorithm algorithm = factory.CreateAggregatedAlgorithm(
                        outer, scope, parameters, type
                    );
                    // проверить наличие алгоритма
                    if (algorithm != null) return algorithm;
                }
                // для всех программных провайдеров
                foreach (Factory factory in factories)
                {
                    // проверить тип фабрики
                    if (!(factory is Software.CryptoProvider)) continue; 

                    // создать алгоритм
                    IAlgorithm algorithm = factory.CreateAggregatedAlgorithm(
                        outer, scope, parameters, type
                    );
                    // проверить наличие алгоритма
                    if (algorithm != null) return algorithm;
                }
            }
            // для провайдера алгоритмов
            else if (scope.Provider is CryptoProvider)
            { 
                // выполнить преобразование типа
                CryptoProvider provider = (CryptoProvider)scope.Provider; 

                // создать алгоритм
                IAlgorithm algorithm = provider.CreateAggregatedAlgorithm(
                    outer, scope, parameters, type
                );
                // проверить наличие алгоритма
                if (algorithm != null) return algorithm;
            }
            return null; 
        }
    }
}
