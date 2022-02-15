using System; 
using System.Diagnostics.CodeAnalysis; 

namespace Aladdin.CAPI
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм генерации ключей
	///////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
	public abstract class KeyPairGenerator : RefObject, IAlgorithm
	{
        // фабрика алгоритмов и область видимости
        private Factory factory; private SecurityObject scope; private IRand rand; 
    
        // конструктор
        public KeyPairGenerator(Factory factory, SecurityObject scope, IRand rand)
        { 
            // сохранить переданные параметры
            this.factory = RefObject.AddRef(factory);
            this.scope   = RefObject.AddRef(scope  ); 
            this.rand    = RefObject.AddRef(rand   ); 
		}
        // освободить выделенные ресурсы
        protected override void OnDispose()
        {
            // освободить выделенные ресурсы
            RefObject.Release(rand); RefObject.Release(scope); 
            
            // освободить выделенные ресурсы
            RefObject.Release(factory); base.OnDispose();
        }
        // фабрика алгоритмов
        protected Factory Factory { get { return factory; }}
        // область видимости
        protected SecurityObject Scope { get { return scope; }}
        // генератор случайных данных
        protected IRand Rand { get { return rand; }} 

        // сгенерировать ключи
		public abstract KeyPair Generate(byte[] keyID, 
            string keyOID, KeyUsage keyUsage, KeyFlags keyFlags
        ); 
	}
}
