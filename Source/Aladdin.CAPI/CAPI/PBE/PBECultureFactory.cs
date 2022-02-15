using System; 
using System.Diagnostics.CodeAnalysis; 

namespace Aladdin.CAPI.PBE
{
    ///////////////////////////////////////////////////////////////////////////////
    // Указание параметров парольной защиты
    ///////////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
    public abstract class PBECultureFactory : RefObject, IPBECultureFactory 
    {
        // получить параметры парольной защиты
        public abstract PBECulture GetCulture(object window, string keyOID); 

        ///////////////////////////////////////////////////////////////////////////
        // Фиксированные параметры парольной защиты
        ///////////////////////////////////////////////////////////////////////////
        public class Fixed : PBECultureFactory
        {
            // конструктор
            public Fixed(PBECulture culture)
             
                // сохранить переданные параметры
                { this.culture = culture; } private PBECulture culture; 

            // получить параметры парольной защиты
            public override PBECulture GetCulture(
                object window, string keyOID) { return culture; }
        }
        ///////////////////////////////////////////////////////////////////////////
        // Параметры парольной защиты по умолчанию
        ///////////////////////////////////////////////////////////////////////////
        public class Default : PBECultureFactory
        {
            // фабрика создания алгоритмов и параметры парольной защиты
            private Factory factory; private PBEParameters parameters;
        
            // конструктор
            public Default(Factory factory, PBEParameters parameters)
            {
                // сохранить переданные параметры
                this.factory = RefObject.AddRef(factory); this.parameters = parameters; 
            }
            // деструктор
            protected override void OnDispose()
            {
                // освободить используемые ресурсы
                RefObject.Release(factory); base.OnDispose();
            }
            // получить параметры парольной защиты
            public override PBECulture GetCulture(object window, string keyOID) 
            { 
                // получить параметры парольной защиты
                return factory.GetCulture(parameters, keyOID); 
            }
        }
    }
}
