using System; 
using System.Diagnostics.CodeAnalysis; 

namespace Aladdin.CAPI
{
    ///////////////////////////////////////////////////////////////////////////
	// Выработка подписи данных
    ///////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
	public abstract class SignData : RefObject, IAlgorithm
	{
        // конструктор
        public SignData() { privateKey = null; } private IPrivateKey privateKey; 

        // деструктор
        protected override void OnDispose()
        {
            // освободить выделенные ресурсы
            RefObject.Release(privateKey); base.OnDispose();
        }
        // используемый личный ключ
        protected IPrivateKey PrivateKey { get { return privateKey; }}

        // алгоритм подписи хэш-значения
        public virtual SignHash SignHashAlgorithm { get { return null; }}

	    // подписать данные
	    public byte[] Sign(IPrivateKey privateKey, IRand rand, byte[] data, int dataOff, int dataLen)
	    {
		    // подписать данные
		    Init(privateKey, rand); Update(data, dataOff, dataLen); return Finish(rand);
	    }
		// инициализировать алгоритм
		public virtual void Init(IPrivateKey privateKey, IRand rand)
        {
            // освободить выделенные ресурсы
            RefObject.Release(this.privateKey); 

            // сохранить переданные параметры
            this.privateKey = RefObject.AddRef(privateKey); 
        }
		// обработать данные
		public abstract void Update(byte[] data, int dataOff, int dataLen);

		// получить подпись данных
        public virtual byte[] Finish(IRand rand)
        {
            // освободить выделенные ресурсы
            RefObject.Release(privateKey); privateKey = null; return null; 
        }
	}
}
