using System;

namespace Aladdin.CAPI.STB.Sign.STB11762
{
    ///////////////////////////////////////////////////////////////////////
    // Алгоритм проверки подписи СТБ 1176.2 на основе хэш-значения СТБ 1176.1
    ///////////////////////////////////////////////////////////////////////
    public class VerifyDataPro : CAPI.VerifyData
    {
        // алгоритм проверки подписи и алгоритм хэширования
        private CAPI.VerifyHash verifyAlgorithm; private CAPI.Hash hashAlgorithm; 
    
        // конструктор
        public VerifyDataPro(CAPI.VerifyHash verifyAlgorithm)
        {
            // сохранить переданные параметры
            this.verifyAlgorithm = RefObject.AddRef(verifyAlgorithm); hashAlgorithm = null;
        }
        // освободить выделенные ресурсы
        protected override void OnDispose()
        {
            // освободить выделенные ресурсы
            RefObject.Release(hashAlgorithm); 
            
            // освободить выделенные ресурсы
            RefObject.Release(verifyAlgorithm); base.OnDispose();
        }
	    // инициализировать алгоритм
	    public override void Init(IPublicKey publicKey, byte[] signature) 
	    {
            // освободить выделенные ресурсы
            RefObject.Release(hashAlgorithm); hashAlgorithm = null; 

            // выполнить преобразование типа
            STB.STB11762.IBDSParameters parameters = 
                (STB.STB11762.IBDSParameters)publicKey.Parameters; 

            // создать алгоритм хэширования
            hashAlgorithm = CreateHashAlgorithm(publicKey, parameters.H); 

            // проверить наличие алгоритма хэширования
            if (hashAlgorithm == null) throw new NotSupportedException();
			
		    // инициализировать алгоритм хэширования
		    base.Init(publicKey, signature); hashAlgorithm.Init(); 
	    }
	    // обработать данные
	    public override void Update(byte[] data, int dataOff, int dataLen)
	    {
		    // прохэшировать данные
		    hashAlgorithm.Update(data, dataOff, dataLen); 
	    }
	    // получить подпись данных
        public override void Finish()
	    {
            // получить хэш-значение
            byte[] hash = new byte[hashAlgorithm.HashSize]; hashAlgorithm.Finish(hash, 0); 

		    // проверить подпись хэш-значения
		    try { verifyAlgorithm.Verify(PublicKey, null, hash, Signature); }

            // освободить выделенные ресурсы
            finally { RefObject.Release(hashAlgorithm); hashAlgorithm = null; } 
	    }
        // создать алгоритм хэширования
        protected CAPI.Hash CreateHashAlgorithm(IPublicKey publicKey, byte[] start) 
        { 
            // создать алгоритм хэширования
            return new Hash.STB11761(start);     
        }
    }
}
