using System;
using System.Collections.Generic;

namespace Aladdin.CAPI
{
    ///////////////////////////////////////////////////////////////////////////
    // Агрегированная фабрика алгоритмов
    ///////////////////////////////////////////////////////////////////////////
    public sealed class AggregatedFactory : Factory
    {
        // внешняя и внутренняя фабрики алгоритмов
        private Factory outer; private Factory factory; 
        
        // конструктор
        public static Factory Create(Factory outer, Factory factory)
        {
            // проверить совпадение ссылок
            if (outer == factory) return RefObject.AddRef(factory); 
        
            // создать агрегированную фабрику алгоритмов
            return new AggregatedFactory(outer, factory); 
        }
        // конструктор
        private AggregatedFactory(Factory outer, Factory factory)
        {
            // сохранить переданные параметры
            this.outer   = RefObject.AddRef(outer  ); 
            this.factory = RefObject.AddRef(factory); 
        }
        // освободить используемые ресурсы
        protected override void OnDispose()
        {
            // освободить используемые ресурсы
            RefObject.Release(outer); RefObject.Release(factory); base.OnDispose();
        }
        // поддерживаемые ключи
        public override Dictionary<String, SecretKeyFactory> SecretKeyFactories() 
        { 
            // поддерживаемые ключи
            return outer.SecretKeyFactories(); 
        }
        public override Dictionary<String, KeyFactory> KeyFactories() 
        { 
            // поддерживаемые ключи
            return outer.KeyFactories(); 
        }
        public override KeyPairGenerator CreateGenerator(
            SecurityObject scope, IRand rand, string keyOID, IParameters parameters)
        {
            // создать алгоритм генерации ключей
            return factory.CreateGenerator(this, scope, rand, keyOID, parameters);
        }
        public override IAlgorithm CreateAlgorithm(
            SecurityStore scope, string oid, ASN1.IEncodable parameters, Type type)
        {
            // для программных алгоритмов
            if (scope == null || scope is Software.ContainerStore)
            {
                // создать алгоритм из внутренней фабрики
                IAlgorithm algorithm = factory.CreateAlgorithm(this, scope, oid, parameters, type);
                
                // проверить наличие алгоритма
                if (algorithm != null) return algorithm; 
                
                // создать алгоритм из внешней фабрики
                return outer.CreateAlgorithm(scope, oid, parameters, type); 
            }
            // для симметричных алгоритмов
            if (type != typeof(SignHash         ) || type != typeof(SignData           ) || 
                type != typeof(IKeyAgreement    ) || type != typeof(ITransportAgreement) || 
                type != typeof(TransportKeyWrap))
            {
                // создать алгоритм из внутренней фабрики
                IAlgorithm algorithm = factory.CreateAlgorithm(this, scope, oid, parameters, type);
                
                // проверить наличие алгоритма
                if (algorithm != null) return algorithm; 
                
                // создать алгоритм из внешней фабрики
                return outer.CreateAlgorithm(scope, oid, parameters, type); 
            }
            // создать асимметричный алгоритм из внутренней фабрики
            else return factory.CreateAlgorithm(this, scope, oid, parameters, type);
        }
    }
}
