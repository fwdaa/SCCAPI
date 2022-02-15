using System; 
using System.IO; 
using System.Diagnostics.CodeAnalysis;

namespace Aladdin.CAPI.KZ.Keyx.Tumar.GOST34310
{
    ///////////////////////////////////////////////////////////////////////////////
    // Алгоритм формирования общего ключа
    ///////////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
    public class TransportAgreement : RefObject, ITransportAgreement
    {
        // параметры алгоритма
        private ASN1.ISO.AlgorithmIdentifier parameters; 

        // конструктор
        public TransportAgreement(ASN1.ISO.AlgorithmIdentifier parameters) 
        { 
            // сохранить переданные параметры
            this.parameters = parameters; 
        } 
        // действия стороны-отправителя
        public virtual TransportAgreementData Wrap(IPrivateKey privateKey, 
            IPublicKey publicKey, IPublicKey[] recipientPublicKeys, IRand rand, ISecretKey CEK)
        {
            // выделить буфер требуемого размера
            byte[][] encryptedKeys = new byte[recipientPublicKeys.Length][]; 

            // создать алгоритм согласования ключа
            using (IKeyAgreement keyAgreement = 
                privateKey.Factory.CreateAlgorithm<IKeyAgreement>(
                    privateKey.Scope, parameters))
            {    
                // проверить наличие алгоритма
                if (keyAgreement == null) throw new NotSupportedException(); 

                // для всех получателей
                for (int i = 0; i < recipientPublicKeys.Length; i++)
                { 
                    // сгенерировать синхропосылку
                    byte[] iv = new byte[8]; rand.Generate(iv, 0, iv.Length); 

                    // получить алгоритм шифрования ключа
                    using (KeyWrap keyWrap = GetKeyWrapAlgorithm(privateKey.Factory, privateKey.Scope, iv))
                    {
                        // сгенерировать случайные данные
                        byte[] ukm = new byte[8]; rand.Generate(ukm, 0, ukm.Length); 

                        // вычислить ключ шифрования ключа шифрования данных
                        using (ISecretKey KEK = keyAgreement.DeriveKey(
                            privateKey, recipientPublicKeys[i], ukm, keyWrap.KeyFactory, 32))
                        {
                            // зашифровать ключ
                            byte[] wrappedCEK = keyWrap.Wrap(rand, KEK, CEK); 
        
                            // извлечь первый блок
                            byte[] spc = Arrays.CopyOf(wrappedCEK, 0, 8); 
        
                            // извлечь оставшиеся данные
                            byte[] encrypted = Arrays.CopyOf(wrappedCEK, 8, wrappedCEK.Length - 8); 
        
                            // закодировать зашифрованный ключ
                            ASN1.KZ.EncryptedKey encryptedKey = new ASN1.KZ.EncryptedKey(
                                new ASN1.Integer(4), new ASN1.OctetString(iv), new ASN1.OctetString(spc), 
                                new ASN1.OctetString(encrypted), new ASN1.OctetString(ukm)
                            ); 
                            // указать заголовок данных
                            byte[] blobHeader = new byte[] { 
                                (byte)0x01, (byte)0x02, (byte)0x00, (byte)0x00, // SIMPLEBLOB
                                (byte)0x1F, (byte)0x68, (byte)0x04, (byte)0x00, // CALG_TG28147-CFB
                                (byte)0x1F, (byte)0x68, (byte)0x00, (byte)0x00, // CALG_TG28147
                            }; 
                            // объединить заголовок к зашифрованному ключу
                            encryptedKeys[i] = Arrays.Concat(blobHeader, encryptedKey.Encoded); 
                        }
                    }
                }
            }
            // вернуть зашифрованные ключи
            return new TransportAgreementData(publicKey, null, encryptedKeys); 
        }
        // действия стороны-получателя
        public virtual ISecretKey Unwrap(IPrivateKey privateKey, IPublicKey publicKey, 
            byte[] random, byte[] wrappedCEK, SecretKeyFactory keyFactory) 
        {
            // проверить размер данных
            if (wrappedCEK.Length < 12) throw new InvalidDataException(); 

            // проверить корректность заголовка
            if (wrappedCEK[0] != 1 || wrappedCEK[1] != 2) throw new InvalidDataException();

            // раскодировать зашифрованный ключ
            ASN1.KZ.EncryptedKey encryptedKey = new ASN1.KZ.EncryptedKey(
                ASN1.Encodable.Decode(wrappedCEK, 12, wrappedCEK.Length - 12)
            );
            // проверить корректность данных
            if (encryptedKey.Spc.Value.Length != 8) throw new InvalidDataException();

            // объединить первый зашифрованный блок с зашифрованными данными
            wrappedCEK = Arrays.Concat(encryptedKey.Spc.Value, encryptedKey.Encrypted.Value); 
    
            // извлечь синхропосылку и UKM
            byte[] iv = encryptedKey.IV.Value; byte[] ukm = encryptedKey.UKM.Value; 

            // создать алгоритм согласования ключа
            using (IKeyAgreement keyAgreement = 
                privateKey.Factory.CreateAlgorithm<IKeyAgreement>(
                    privateKey.Scope, parameters))
            {    
                // проверить наличие алгоритма
                if (keyAgreement == null) throw new NotSupportedException(); 

                // получить алгоритм шифрования ключа
                using (KeyWrap keyWrap = GetKeyWrapAlgorithm(privateKey.Factory, privateKey.Scope, iv))
                {
                    // вычислить ключ шифрования ключа шифрования данных
                    using (ISecretKey KEK = keyAgreement.DeriveKey(
                        privateKey, publicKey, ukm, keyWrap.KeyFactory, 32))
                    {
                        // расшифровать ключ
                        return keyWrap.Unwrap(KEK, wrappedCEK, keyFactory); 
                    }
                }
            }
        }
        // создать алгоритм шифрования ключа
        protected virtual KeyWrap GetKeyWrapAlgorithm(
            CAPI.Factory factory, SecurityStore scope, byte[] iv)
        {
            // указать параметры алгоритма шифрования
            ASN1.ISO.AlgorithmIdentifier cipherParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.KZ.OID.gamma_cipher_gost_cfb), 
                new ASN1.OctetString(iv)
            ); 
            // создать алгоритм шифрования 
            using (CAPI.Cipher cipher = 
                factory.CreateAlgorithm<CAPI.Cipher>(scope, cipherParameters))
            {
                // проверить наличие алгоритма
                if (cipher == null) throw new NotSupportedException(); 
            
                // создать алгоритм шифрования ключа
                return new Wrap.KeyWrap(cipher, null); 
            }
        }
    }
}
