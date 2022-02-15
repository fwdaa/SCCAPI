using System;

namespace Aladdin.CAPI.STB.Sign.STB11762
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм проверки подписи хэш-значения СТБ 1176.2
    ///////////////////////////////////////////////////////////////////////////
    public class VerifyHash : CAPI.VerifyHash
    {
        // алгоритм проверки подписи данных
        private CAPI.VerifyData verifyAlgorithm; 
        
        // конструктор
        public VerifyHash(CAPI.VerifyData verifyAlgorithm)
        {
            // сохранить переданные параметры
            this.verifyAlgorithm = RefObject.AddRef(verifyAlgorithm); 
        }
        // освободить используемые ресурсы
        protected override void OnDispose() 
        {
            // освободить используемые ресурсы
            RefObject.Release(verifyAlgorithm); base.OnDispose(); 
        }
        public override void Verify(IPublicKey publicKey, 
            ASN1.ISO.AlgorithmIdentifier hashParameters, byte[] data, byte[] signature) 
        {
            // проверить подпись данных
            verifyAlgorithm.Verify(publicKey, data, 0, data.Length, signature); 
        }
    }
}
