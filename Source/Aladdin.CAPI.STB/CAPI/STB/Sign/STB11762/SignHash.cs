using System;

namespace Aladdin.CAPI.STB.Sign.STB11762
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм выработки подписи хэш-значения СТБ 1176.2
    ///////////////////////////////////////////////////////////////////////////
    public class SignHash : CAPI.SignHash
    {
        // алгоритм подписи данных
        private CAPI.SignData signAlgorithm; 
        
        // конструктор
        public SignHash(CAPI.SignData signAlgorithm) 
        { 
            // сохранить переданные параметры
            this.signAlgorithm = RefObject.AddRef(signAlgorithm); 
        }
        // освободить используемые ресурсы
        protected override void OnDispose() 
        {
            // освободить используемые ресурсы
            RefObject.Release(signAlgorithm); base.OnDispose(); 
        }
        public override byte[] Sign(IPrivateKey privateKey, 
            IRand rand, ASN1.ISO.AlgorithmIdentifier hashParameters, byte[] data)
        {
            while (true) 
            {
                // подписать данные
                try { return signAlgorithm.Sign(privateKey, rand, data, 0, data.Length); } 

                // обработать ошибку
                catch (InvalidOperationException) {} 
            }
        }
    }
}
