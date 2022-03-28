using System; 
using System.Diagnostics.CodeAnalysis; 

namespace Aladdin.CAPI.PBE
{
    ///////////////////////////////////////////////////////////////////////////////
    // Указание параметров парольной защиты
    ///////////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
    public abstract class PBECultureFactory : IPBECultureFactory 
    {
        // получить параметры парольной защиты
        public abstract PBECulture GetPBECulture(object window, string keyOID); 

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
            public override PBECulture GetPBECulture(
                object window, string keyOID) { return culture; }
        }
    }
}
