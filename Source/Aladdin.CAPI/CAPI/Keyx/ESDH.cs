using System; 
using System.Diagnostics.CodeAnalysis; 

namespace Aladdin.CAPI.Keyx
{
    ///////////////////////////////////////////////////////////////////////////
    // Формирование общего ключа Ephemeral-Static Diffie-Hellman
    ///////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
    public class ESDH : RefObject, ITransportAgreement
    {
        // фабрика алгоритмов и алгоритм формирования общего ключа
        private Factory factory; private ITransportAgreement ssdh;

        // конструктор
        public ESDH(Factory factory, ITransportAgreement ssdh)
        {
            // сохранить переданные параметры
            this.factory = RefObject.AddRef(factory); 
            this.ssdh    = RefObject.AddRef(ssdh   ); 
        }
        // освободить выделенные ресурсы
        protected override void OnDispose()
        {
            // освободить выделенные ресурсы
            RefObject.Release(ssdh); RefObject.Release(factory); base.OnDispose();
        }
        // действия стороны-отправителя
        public virtual TransportAgreementData Wrap(
            IPrivateKey senderPrivateKey, IPublicKey senderPublicKey, 
            IPublicKey[] recipientPublicKeys, IRand rand, ISecretKey key)
        {
            // создать алгорим генерации ключей
            using (KeyPairGenerator generator = factory.CreateGenerator(
                null, recipientPublicKeys[0].KeyOID, recipientPublicKeys[0].Parameters, rand))
            {  
                // сгенерировать эфемерную пару ключей
                using (KeyPair keyPair = generator.Generate(null, 
                    recipientPublicKeys[0].KeyOID, KeyUsage.KeyAgreement, KeyFlags.None))
                {
                    // зашифровать ключ
                    return ssdh.Wrap(keyPair.PrivateKey, keyPair.PublicKey, recipientPublicKeys, rand, key); 
                }
            }
        }
        // действия стороны-получателя
        public virtual ISecretKey Unwrap(IPrivateKey recipientPrivateKey, 
            IPublicKey publicKey, byte[] random, byte[] encryptedKey, SecretKeyFactory keyFactory)
        {
            // расшифровать ключ
            return ssdh.Unwrap(recipientPrivateKey, publicKey, random, encryptedKey, keyFactory); 
        }
    }
}
