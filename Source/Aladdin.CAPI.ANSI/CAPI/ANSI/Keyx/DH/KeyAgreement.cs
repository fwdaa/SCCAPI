using System; 

namespace Aladdin.CAPI.ANSI.Keyx.DH
{
    ///////////////////////////////////////////////////////////////////////////
    // Формирование общего ключа Diffie-Hellman
    ///////////////////////////////////////////////////////////////////////////
    public class KeyAgreement : CAPI.KeyAgreement
    {
        // способ кодирования чисел
        private const Math.Endian Endian = Math.Endian.BigEndian; 

        // алгоритм наследования ключа
        private KeyDerive keyDerive; 

        // конструктор
        public KeyAgreement(KeyDerive keyDerive)
        { 
            // сохранить переданные параметры
            this.keyDerive = RefObject.AddRef(keyDerive); 
        } 
        // конструктор
        public KeyAgreement() { keyDerive = new CAPI.Derive.NOKDF(Endian); }

        // конструктор
        public KeyAgreement(CAPI.Hash hashAlgorithm, string wrapOID)
        { 
            // создать алгоритм наследования ключа
            keyDerive = new Derive.X942KDF(hashAlgorithm, wrapOID); 
        } 
        // освободить используемые ресурсы
        protected override void OnDispose() 
        {
            // освободить используемые ресурсы
            RefObject.Release(keyDerive); base.OnDispose();
        }
        // сгенерировать случайные данные
        public override byte[] Generate(IParameters parameters, IRand rand)
        {
            // проверить необходимость генерации
            if (keyDerive is CAPI.Derive.NOKDF) return null; 

            // сгенерировать случайные данные
            byte[] random = new byte[64]; rand.Generate(random, 0, 64); return random;   
        }
        // наследовать ключ
        public override ISecretKey DeriveKey(IPrivateKey privateKey, 
            IPublicKey publicKey, byte[] random, SecretKeyFactory keyFactory, int keySize)
        {
            // вычислить секретное число
            using (ISecretKey ZZ = keyDerive.KeyFactory.Create(DeriveKey(privateKey, publicKey)))
            { 
                // выполнить наследование ключа
                return keyDerive.DeriveKey(ZZ, random, keyFactory, keySize); 
            }
        }
        protected virtual byte[] DeriveKey(IPrivateKey privateKey, IPublicKey publicKey)
        {
            // преобразовать тип данных
            ANSI.X942.IPrivateKey privateKeyX = (ANSI.X942.IPrivateKey)privateKey; 
            ANSI.X942.IPublicKey  publicKeyX  = (ANSI.X942.IPublicKey )publicKey; 

            // получить параметры алгоритма
            ANSI.X942.IParameters parameters = (ANSI.X942.IParameters)privateKey.Parameters; 

            // вычислить секретное число
            Math.BigInteger Z = publicKeyX.Y.ModPow(privateKeyX.X, parameters.P); 

            // закодировать секретное число
            return Math.Convert.FromBigInteger(Z, Endian, (parameters.P.BitLength + 7) / 8);
        }
    }
}
