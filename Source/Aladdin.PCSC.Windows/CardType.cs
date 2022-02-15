using System;

namespace Aladdin.PCSC.Windows
{
    ///////////////////////////////////////////////////////////////////////////
    // Тип смарт-карты
    ///////////////////////////////////////////////////////////////////////////
    public class CardType
    {
	    // модуль, область видимости и имя типа
	    private Module module; private ReaderScope scope; private String name; 

	    // конструктор
	    public CardType(Module module, ReaderScope scope, String name) 
        { 
            // сохранить переданные параметры
            this.module = module; this.scope = scope; this.name = name;
	    }
	    // имя типа смарт-карты
	    public String Name { get { return name; }} 

        // идентификатор первичного провайдера
        public Guid GetPrimaryProvider() 
        { 
	        // создать используемый контекст
	        ulong hContext = module.EstablishContext(scope); 
            try {
                // получить идентификатор первичного провайдера
                return module.GetCardTypePrimaryProvider(hContext, name); 
            }
            // освободить выделенные ресурсы
            finally { module.ReleaseContext(hContext); } 
        } 
        // идентификаторы интерфейсов
	    public Guid[] GetInterfaces()
        {
	        // создать используемый контекст
	        ulong hContext = module.EstablishContext(scope); 
            try {
                // получить идентификаторы интерфейсов
                return module.GetCardTypeInterfaces(hContext, name); 
            }
            // освободить выделенные ресурсы
            finally { module.ReleaseContext(hContext); } 
        }
        // получить имя провайдера
        public string GetProviderCSP() 
        { 
	        // создать используемый контекст
	        ulong hContext = module.EstablishContext(scope); 
            try {
                // получить имя провайдера
                return module.GetCardTypeProvider(
                    hContext, name, NativeMethods.SCARD_PROVIDER_CSP
                ); 
            }
            // освободить выделенные ресурсы
            finally { module.ReleaseContext(hContext); } 
        } 
        // установить имя провайдера
        public void SetProviderCSP(string providerName) 
        { 
	        // создать используемый контекст
	        ulong hContext = module.EstablishContext(scope); 
            try {
                // установить имя провайдера
                module.SetCardTypeProvider(hContext, 
                    name, NativeMethods.SCARD_PROVIDER_CSP, providerName
                ); 
            }
            // освободить выделенные ресурсы
            finally { module.ReleaseContext(hContext); } 
        } 
        // получить имя провайдера
        public string GetProviderKSP() 
        { 
	        // создать используемый контекст
	        ulong hContext = module.EstablishContext(scope); 
            try {
                // получить имя провайдера
                return module.GetCardTypeProvider(
                    hContext, name, NativeMethods.SCARD_PROVIDER_KSP
                ); 
            }
            // освободить выделенные ресурсы
            finally { module.ReleaseContext(hContext); } 
        } 
        // установить имя провайдера
        public void SetProviderKSP(string providerName) 
        { 
	        // создать используемый контекст
	        ulong hContext = module.EstablishContext(scope); 
            try {
                // установить имя провайдера
                module.SetCardTypeProvider(hContext, 
                    name, NativeMethods.SCARD_PROVIDER_KSP, providerName
                ); 
            }
            // освободить выделенные ресурсы
            finally { module.ReleaseContext(hContext); } 
        } 
    }
}
