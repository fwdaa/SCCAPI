namespace Aladdin.CAPI
{
    ///////////////////////////////////////////////////////////////////////////
    // Фильтр выбора фабрик
    ///////////////////////////////////////////////////////////////////////////
    public abstract class FactoryFilter
    {
        // проверить допустимость фабрики
        public abstract bool IsMatch(Factory factory);

        ///////////////////////////////////////////////////////////////////////
        // Фильтр программных фабрик
        ///////////////////////////////////////////////////////////////////////
        public class Software : FactoryFilter
        {
            // конструктор
            public Software(FactoryFilter filter)

                // сохранить переданные параметры
                { this.filter = filter; } private FactoryFilter filter;

            // проверить допустимость фабрики
            public override bool IsMatch(Factory factory)
            {
                // проверить тип фабрики
                if (factory is CryptoProvider)
                { 
                    // проверить тип фабрики
                    if (!(factory is CAPI.Software.CryptoProvider)) return false;
                }
                // вызвать функцию фильтра
                return (filter == null) || filter.IsMatch(factory);
            }
        }
        ///////////////////////////////////////////////////////////////////////
        // Фильтр провайдеров
        ///////////////////////////////////////////////////////////////////////
        public class Provider : FactoryFilter
        {
            // конструктор
            public Provider(FactoryFilter filter)

                // сохранить переданные параметры
                { this.filter = filter; } private FactoryFilter filter;

            // проверить допустимость фабрики
            public override bool IsMatch(Factory factory)
            {
                // проверить тип фабрики
                if (!(factory is CryptoProvider)) return false;

                // проверить тип фабрики
                if (factory is CAPI.Software.CryptoProvider) return false;

                // вызвать функцию фильтра
                return (filter == null) || filter.IsMatch(factory);
            }
        }
    }
}
