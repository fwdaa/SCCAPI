using System; 
using System.Diagnostics.CodeAnalysis; 

namespace Aladdin.CAPI
{
    ///////////////////////////////////////////////////////////////////////////
	// Проверка подписи данных
    ///////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
	public abstract class VerifyData : RefObject, IAlgorithm
	{
        // используемый открытый ключ и проверяемая подпись
        private IPublicKey publicKey; private byte[] signature;

        // конструктор
        public VerifyData() { publicKey = null; signature = null; } 
    
        // используемый открытый ключ
        protected IPublicKey PublicKey { get { return publicKey; }}
        // проверяемая подпись
        protected byte[] Signature { get { return signature; }}
    
        // алгоритм проверки подписи хэш-значения
        public virtual VerifyHash VerifyHashAlgorithm { get { return null; }}

	    // проверить подпись данных
	    public void Verify(IPublicKey publicKey, 
            byte[] data, int dataOff, int dataLen, byte[] signature) 
	    {
		    // проверить подпись данных
		    Init(publicKey, signature); Update(data, dataOff, dataLen); Finish();
	    }
		// обработать данные
		public virtual void Init(IPublicKey publicKey, byte[] signature)
        {
            // сохранить переданные параметры
            this.publicKey = publicKey; this.signature = signature; 
        }
        // обработать данные
        public abstract void Update(byte[] data, int dataOff, int dataLen);

        // проверить подпись данных
        public abstract void Finish();
	}
}
