using System; 
using System.Diagnostics.CodeAnalysis; 

namespace Aladdin.CAPI
{
	///////////////////////////////////////////////////////////////////////////
	// Личный ключ алгоритма
	///////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
	public abstract class PrivateKey : RefObject, IPrivateKey
	{
		private Factory        factory;	// фабрика алгоритмов
        private SecurityObject scope;   // область видимости
        private String         keyOID;  // идентификатор ключа

        // конструктор
        public PrivateKey(Factory factory, SecurityObject scope, string keyOID)
		{
            // сохранить фабрику алгоритмов
            this.factory = RefObject.AddRef(factory); 

            // сохранить область видимости
            this.scope = RefObject.AddRef(scope); this.keyOID = keyOID; 
		}
		// конструктор
		protected PrivateKey(PrivateKey privateKey)
		{
            // сохранить фабрику алгоритмов
            factory = RefObject.AddRef(privateKey.factory); 

            // сохранить область видимости
            scope = RefObject.AddRef(privateKey.scope); 

            // сохранить идентификатор ключа
            this.keyOID = privateKey.KeyOID; 
        }
        // освободить выделенные ресурсы
        protected override void OnDispose() 
        {
            // освободить выделенные ресурсы
            RefObject.Release(scope); 

            // освободить выделенные ресурсы
            RefObject.Release(factory); base.OnDispose();
        }
        // фабрика алгоритмов
		public Factory Factory { get { return factory; }}

        // область видимости ключа
	    public SecurityStore Scope { get  
        { 
            // при указании хранилища контейнеров
            if (scope is SecurityStore)
            {
                // извлечь хранилище контейнеров
                return (SecurityStore)scope; 
            }
            // извлечь хранилище контейнеров
            return (scope != null) ? scope.Store : null; 
        }}
        // контейнер ключа
        public Container Container { get 
        {
            // контейнер ключа
            return (scope is Container) ? (Container)scope : null; 
        }}
        // идентификатор ключа
        public string KeyOID { get { return keyOID; }}

        // параметры ключа 
        public abstract IParameters Parameters { get; } 

        // фабрика кодирования
        public KeyFactory KeyFactory
        {
            // фабрика кодирования
            get { return Factory.GetKeyFactory(keyOID); }
        }
        // закодировать ключ
        public ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo Encode(ASN1.ISO.Attributes attributes)
        {
            // закодировать ключ
            return KeyFactory.EncodePrivateKey(this, attributes); 
        }
    }
}
