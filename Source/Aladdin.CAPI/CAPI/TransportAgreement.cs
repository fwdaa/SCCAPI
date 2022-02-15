using System; 
using System.Diagnostics.CodeAnalysis; 

namespace Aladdin.CAPI
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм ассиметричного шифрования ключа на основе двух алгоритмов
    ///////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
    public class TransportAgreement : RefObject, ITransportAgreement 
    {
        // параметры алгоритма
        private ASN1.ISO.AlgorithmIdentifier parameters; 
    
        // создать алгоритм SSDH
        public static TransportAgreement CreateSSDH(Factory factory, 
            SecurityStore scope, ASN1.ISO.AlgorithmIdentifier parameters) 
        {
            // указать параметры шифрования ключа
            ASN1.ISO.AlgorithmIdentifier keyWrapParameters = 
                new ASN1.ISO.AlgorithmIdentifier(parameters.Parameters); 
        
            // создать алгоритм шифрования ключа
            using (IAlgorithm keyWrap = 
                factory.CreateAlgorithm<KeyWrap>(scope, keyWrapParameters))
            {
                // проверить поддержку алгоритма
                if (keyWrap == null) return null;  
            }
            // создать алгоритм согласования ключа
            using (IAlgorithm keyAgreement = 
                factory.CreateAlgorithm<IKeyAgreement>(scope, parameters))
            {
                // проверить поддержку алгоритма
                if (keyAgreement == null) return null;  
            }
            // создать алгоритм шифрования ключа
            return new TransportAgreement(parameters); 
        }
        // конструктор
        public TransportAgreement(ASN1.ISO.AlgorithmIdentifier parameters) 
        { 
            // сохранить переданные параметры
            this.parameters = parameters; 
        }
        // действия стороны-отправителя
        public virtual TransportAgreementData Wrap(IPrivateKey privateKey, 
            IPublicKey publicKey, IPublicKey[] recipientPublicKeys, IRand rand, ISecretKey key) 
        {
            // выделить буфер требуемого размера
            byte[][] encryptedKeys = new byte[recipientPublicKeys.Length][]; 
        
            // создать алгоритм согласования ключа
            using (KeyAgreement keyAgreement = CreateKeyAgreementAlgorithm(
                privateKey.Factory, privateKey.Scope, parameters))
            {    
                // сгенерировать случайные данные
                byte[] random = keyAgreement.Generate(publicKey.Parameters, rand); 

                // создать алгоритм шифрования ключа
                using (KeyWrap keyWrap = CreateKeyWrapAlgorithm(
                    privateKey.Factory, privateKey.Scope, parameters, random)) 
                {
                    // определить допустимые размеры ключей
                    int[] keySizes = keyWrap.KeySizes; int keySize = -1; 
        
                    // указать рекомендуемый размер ключа
                    if (keySizes != null && keySizes.Length == 1) keySize = keySizes[0]; 
        
                    // для всех получателей
                    for (int i = 0; i < recipientPublicKeys.Length; i++)
                    { 
                        // вычислить ключ шифрования ключа шифрования данных
                        using (ISecretKey KEK = keyAgreement.DeriveKey(privateKey, 
                            recipientPublicKeys[i], random, keyWrap.KeyFactory, keySize)) 
                        {
                            // проверить допустимость размера ключа
                            if (!KeySizes.Contains(keySizes, KEK.Length)) 
                            {
                                // выбросить исключение
                                throw new InvalidOperationException();
                            }
                            // зашифровать ключ
                            encryptedKeys[i] = EncodeEncryptedKey(keyWrap.Wrap(rand, KEK, key)); 
                        }
                    }
                }
                // вернуть зашифрованные ключи
                return new TransportAgreementData(publicKey, random, encryptedKeys); 
            }
        }
        // действия стороны-получателя
        public virtual ISecretKey Unwrap(IPrivateKey privateKey, IPublicKey publicKey, 
            byte[] random, byte[] encryptedKey, SecretKeyFactory keyFactory) 
        {
            // создать алгоритм согласования ключа
            using (KeyAgreement keyAgreement = CreateKeyAgreementAlgorithm(
                privateKey.Factory, privateKey.Scope, parameters))
            {    
                // создать алгоритм шифрования ключа
                using (KeyWrap keyWrap = CreateKeyWrapAlgorithm(
                    privateKey.Factory, privateKey.Scope, parameters, random)) 
                {
                    // определить допустимые размеры ключей
                    int[] keySizes = keyWrap.KeySizes; int keySize = -1;  
        
                    // указать рекомендуемый размер ключа
                    if (keySizes != null && keySizes.Length == 1) keySize = keySizes[0]; 
        
                    // вычислить ключ шифрования ключа шифрования данных
                    using (ISecretKey KEK = keyAgreement.DeriveKey(privateKey, 
                        publicKey, random, keyWrap.KeyFactory, keySize)) 
                    {
                        // проверить допустимость размера ключа
                        if (!KeySizes.Contains(keySizes, KEK.Length)) 
                        {
                            // выбросить исключение
                            throw new InvalidOperationException();
                        }
                        // расшифровать ключ
                        return keyWrap.Unwrap(KEK, DecodeEncryptedKey(encryptedKey), keyFactory); 
                    }
                }
            }
        }
        // закодировать/раскодировать зашифрованный ключ
        protected virtual byte[] EncodeEncryptedKey(byte[] encryptedKey) { return encryptedKey; }    
        protected virtual byte[] DecodeEncryptedKey(byte[] encryptedKey) { return encryptedKey; }    
    
        // получить алгоритм согласования ключа
        protected virtual KeyAgreement CreateKeyAgreementAlgorithm(
            Factory factory, SecurityStore scope, ASN1.ISO.AlgorithmIdentifier parameters)
        {
            // создать алгоритм согласования ключа
            KeyAgreement keyAgreement = (KeyAgreement)factory.CreateAlgorithm<IKeyAgreement>(scope, parameters); 
            
            // проверить наличие алгоритма
            if (keyAgreement == null) throw new NotSupportedException(); return keyAgreement; 
        }
        // получить алгоритм шифрования ключа
        protected virtual KeyWrap CreateKeyWrapAlgorithm(Factory factory, 
            SecurityStore scope, ASN1.ISO.AlgorithmIdentifier parameters, byte[] random)
        {
            // указать параметры шифрования ключа
            ASN1.ISO.AlgorithmIdentifier keyWrapParameters = 
                new ASN1.ISO.AlgorithmIdentifier(parameters.Parameters); 
        
            // создать алгоритм шифрования ключа
            KeyWrap keyWrap = factory.CreateAlgorithm<KeyWrap>(scope, keyWrapParameters); 
        
            // проверить поддержку алгоритма
            if (keyWrap == null) throw new NotSupportedException(); return keyWrap; 
        }
    }
}
