using System;

namespace Aladdin.CAPI
{
    ///////////////////////////////////////////////////////////////////////////////
    // Данные, используемые при согласовании ключа
    ///////////////////////////////////////////////////////////////////////////////
    public class TransportAgreementData
    {
        // конструктор
        public TransportAgreementData(IPublicKey publicKey, 
            byte[] random, byte[][] encryptedKeys) 
        { 
            // сохранить переданные параметры
            PublicKey = publicKey; Random = random; EncryptedKeys = encryptedKeys; 
        }
        // открытый ключ
        public readonly IPublicKey PublicKey; 

        // случайные данные и зашифрованный ключ
        public readonly byte[] Random; public readonly byte[][] EncryptedKeys; 
    }
}
