using System;

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
        public override KeyFactory[] KeyFactories() { return outer.KeyFactories(); }

        public override Culture GetCulture(SecurityStore scope, string keyOID) 
        {
            // получить алгоритмы по умолчанию
            Culture culture = factory.GetCulture(scope, keyOID); 
        
            // проверить наличие алгоритмов
            if (culture != null) return culture; 
                
            // создать алгоритмы из внешней фабрики
            return outer.GetCulture(scope, keyOID); 
        }
        public override PBE.PBECulture GetCulture(PBE.PBEParameters parameters, string keyOID) 
        {
            // получить алгоритмы по умолчанию
            PBE.PBECulture culture = factory.GetCulture(parameters, keyOID); 
        
            // проверить наличие алгоритмов
            if (culture != null) return culture; 
                
            // создать алгоритмы из внешней фабрики
            return outer.GetCulture(parameters, keyOID); 
        }
        public override KeyPairGenerator CreateGenerator(
            SecurityObject scope, IRand rand, string keyOID, IParameters parameters)
        {
            // создать алгоритм генерации ключей
            return factory.CreateGenerator(this, scope, rand, keyOID, parameters);
        }
        public override IAlgorithm CreateAlgorithm(
            SecurityStore scope, ASN1.ISO.AlgorithmIdentifier parameters, Type type)
        {
            // для программных алгоритмов
            if (scope == null || scope is Software.ContainerStore)
            {
                // создать алгоритм из внутренней фабрики
                IAlgorithm algorithm = factory.CreateAlgorithm(this, scope, parameters, type);
                
                // проверить наличие алгоритма
                if (algorithm != null) return algorithm; 
                
                // создать алгоритм из внешней фабрики
                return outer.CreateAlgorithm(scope, parameters, type); 
            }
            // для симметричных алгоритмов
            if (type != typeof(SignHash         ) || type != typeof(SignData           ) || 
                type != typeof(IKeyAgreement    ) || type != typeof(ITransportAgreement) || 
                type != typeof(TransportKeyWrap))
            {
                // создать алгоритм из внутренней фабрики
                IAlgorithm algorithm = factory.CreateAlgorithm(this, scope, parameters, type);
                
                // проверить наличие алгоритма
                if (algorithm != null) return algorithm; 
                
                // создать алгоритм из внешней фабрики
                return outer.CreateAlgorithm(scope, parameters, type); 
            }
            // создать асимметричный алгоритм из внутренней фабрики
            else return factory.CreateAlgorithm(this, scope, parameters, type);
        }
    }
}
