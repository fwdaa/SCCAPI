package aladdin.capi.pbe;

///////////////////////////////////////////////////////////////////////////////
// Указание параметров парольной защиты
///////////////////////////////////////////////////////////////////////////////
public abstract class PBECultureFactory implements IPBECultureFactory 
{
    // получить параметры парольной защиты
    @Override public abstract PBECulture getPBECulture(Object window, String keyOID); 

    ///////////////////////////////////////////////////////////////////////////
    // Фиксированные параметры парольной защиты
    ///////////////////////////////////////////////////////////////////////////
    public static class Fixed extends PBECultureFactory
    {
        // конструктор
        public Fixed(PBECulture culture)

            // сохранить переданные параметры
            { this.culture = culture; } private final PBECulture culture; 

        // получить параметры парольной защиты
        @Override public PBECulture getPBECulture(Object window, String keyOID) { return culture; }
    }
}
