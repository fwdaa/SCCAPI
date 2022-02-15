package aladdin.capi;

///////////////////////////////////////////////////////////////////////////
// Фильтр выбора фабрик
///////////////////////////////////////////////////////////////////////////
public abstract class FactoryFilter
{
    // проверить допустимость фабрики
    public abstract boolean isMatch(Factory factory);

    ///////////////////////////////////////////////////////////////////////
    // Фильтр программных фабрик
    ///////////////////////////////////////////////////////////////////////
    public static class Software extends FactoryFilter
    {
        // конструктор
        public Software(FactoryFilter filter)

            // сохранить переданные параметры
            { this.filter = filter; } private final FactoryFilter filter;

        // проверить допустимость фабрики
        @Override public boolean isMatch(Factory factory)
        {
            // проверить тип фабрики
            if (factory instanceof CryptoProvider)
            { 
                // проверить тип фабрики
                if (!(factory instanceof aladdin.capi.software.CryptoProvider)) return false;
            }
            // вызвать функцию фильтра
            return (filter == null) || filter.isMatch(factory);
        }
    }
    ///////////////////////////////////////////////////////////////////////
    // Фильтр провайдеров
    ///////////////////////////////////////////////////////////////////////
    public static class Provider extends FactoryFilter
    {
        // конструктор
        public Provider(FactoryFilter filter)

            // сохранить переданные параметры
            { this.filter = filter; } private final FactoryFilter filter;

        // проверить допустимость фабрики
        @Override public boolean isMatch(Factory factory)
        {
            // проверить тип фабрики
            if (!(factory instanceof CryptoProvider)) return false;

            // проверить тип фабрики
            if (factory instanceof aladdin.capi.software.CryptoProvider) return false;
                
            // вызвать функцию фильтра
            return (filter == null) || filter.isMatch(factory);
        }
    }
}
