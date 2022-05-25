using System; 
using System.Diagnostics.CodeAnalysis; 

namespace Aladdin.CAPI
{
    ///////////////////////////////////////////////////////////////////////
    // Алгоритм согласования ключа
    ///////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
    public abstract class KeyAgreement : RefObject, IKeyAgreement
    {
        // сгенерировать случайные данные
        public abstract byte[] Generate(IParameters parameters, IRand rand);

        // согласовать общий ключ на стороне отправителя
        public virtual DeriveData DeriveKey(IPrivateKey privateKey, 
            IPublicKey publicKey, IRand rand, SecretKeyFactory keyFactory, int keySize)
        {
            // сгенерировать случайные данные
            byte[] random = Generate(privateKey.Parameters, rand); 
    
            // сгенерировать ключ
            using (ISecretKey key = DeriveKey(privateKey, publicKey, random, keyFactory, keySize))
            {
                // вернуть сгенерированные данные
                return new DeriveData(key, random); 
            }
        }
 	    // согласовать общий ключ на стороне получателя
	    public abstract ISecretKey DeriveKey(IPrivateKey privateKey, 
            IPublicKey publicKey, byte[] random, SecretKeyFactory keyFactory, int keySize
        );
        ////////////////////////////////////////////////////////////////////////////
        // Тест известного ответа
        ////////////////////////////////////////////////////////////////////////////
        protected static void KnownTest(SecurityObject scope, IKeyAgreement keyAgreement, 
            IPublicKey publicKey1, IPrivateKey privateKey1,
            IPublicKey publicKey2, IPrivateKey privateKey2,  byte[][] random, byte[] check)
        {
            // указать фабрику кодирования ключей
            SecretKeyFactory keyFactory = SecretKeyFactory.Generic; 

            // импортировать пару в контейнер
            using (KeyPair keyPair1 = new KeyPair(scope, null, 
                publicKey1, privateKey1, null, KeyUsage.KeyAgreement, KeyFlags.None)) 
            {
                // создать эфемерную пару
                using (KeyPair keyPair2 = new KeyPair(publicKey2, privateKey2, null))
                {
                    // создать генератор случайных данных
                    using (IRand rand = new Rnd.Fixed(random)) 
                    {
                        // сформировать общий ключ
                        using (DeriveData kdfData = keyAgreement.DeriveKey(
                            keyPair1.PrivateKey, keyPair2.PublicKey, rand, keyFactory, check.Length))
                        {
                            // извлечь ключ и случайные данные
                            byte[] key = kdfData.Key.Value; 

                            // проверить совпадение результатов
                            if (!Arrays.Equals(key, check)) throw new ArgumentException();
                        }
                    }
                }
            }
        }
    }
}
