using System;

namespace Aladdin.CAPI.SCard
{
    ///////////////////////////////////////////////////////////////////////////
    // Провайдер апплетов
    ///////////////////////////////////////////////////////////////////////////
    public interface IProviderImpl
    {
        // имя провайдера
        string Name { get; }

        // перечислить апплеты
  		string[] EnumerateApplets(Card store); 
        // открыть апплет
        Applet OpenApplet(Card store, string name); 
    }
}
