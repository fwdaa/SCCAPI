using System;
using System.IO;

namespace Aladdin.CAPI.STB.Keyx.STB11762
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм согласования общего ключа на стороне получателе
    ///////////////////////////////////////////////////////////////////////////
    public class TransportKeyUnwrap : CAPI.TransportKeyUnwrap
    {
        // способ кодирования чисел
        private const Math.Endian Endian = Math.Endian.LittleEndian; 

        // алгоритм согласования ключа
        private IKeyAgreement keyAgreement;       

        // конструктор
        public TransportKeyUnwrap(IKeyAgreement keyAgreement) 
        { 
            // сохранить переданные параметры
            this.keyAgreement = RefObject.AddRef(keyAgreement); 
        }  
        // освободить используемые ресурсы
        protected override void OnDispose() 
        {
            // освободить используемые ресурсы
            RefObject.Release(keyAgreement); base.OnDispose();
        }
        public override ISecretKey Unwrap(IPrivateKey privateKey, 
            TransportKeyData transportData, SecretKeyFactory keyFactory) 
        {
            // преобразовать тип параметров
            STB.STB11762.IBDHParameters bdhParameters = 
                (STB.STB11762.IBDHParameters)privateKey.Parameters; 

            // извлечь параметры алгоритма
            int N = bdhParameters.N; Math.BigInteger P = bdhParameters.P;
        
            // проверить размер ключа
            if (N > bdhParameters.L) throw new ArgumentException(); 
        
            // раскодировать переданные параметры
            ASN1.STB.BDHKeyTransParams parameters = 
                new ASN1.STB.BDHKeyTransParams(transportData.Algorithm.Parameters); 
            
            // указать зашифрованное значение
            byte[] eCEK = transportData.EncryptedKey; 

            // прочитать значение нонки
            Math.BigInteger V = parameters.Va.Value; int keySize = (N + 7) / 8; 
        
            // проверить корректность данных
            if (V.Signum == 0 || V.CompareTo(P) >= 0) throw new InvalidDataException();

            // закодировать значение нонки
            byte[] random = Math.Convert.FromBigInteger(parameters.Va.Value, Endian);

            // указать идентификатор таблицы подстановок
            String sboxOID = parameters.SBlock.Value;

            // создать алгоритм шифрования
            using (CAPI.Cipher cipher = CreateCipher(privateKey, sboxOID))
            {                
                // выполнить согласование ключа
                using (ISecretKey KEK = keyAgreement.DeriveKey(
                    privateKey, null, random, cipher.KeyFactory, keySize))
                {
                    // расшифровать данные
                    byte[] CEK = cipher.Decrypt(KEK, PaddingMode.None, eCEK, 0, eCEK.Length); 

                    // получить алгоритм вычисления имитовставки
                    using (Mac macAlgorithm = CreateMacAlgorithm(privateKey, sboxOID))
                    {
                        // вычислить имтовставку ключа
                        byte[] check = macAlgorithm.MacData(KEK, CEK, 0, CEK.Length);

                        // проверить совпадение имитовставок
                        if (!Arrays.Equals(check, parameters.Mac.Value)) throw new InvalidDataException();
                    }
                    // вернуть расшифрованный ключ
                    return keyFactory.Create(CEK);
                }
            }
        }
        // создать алгоритм шифрования
        protected CAPI.Cipher CreateCipher(IPrivateKey privateKey, string sboxOID)
        {
            // закодировать параметры алгоритма
            ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.STB.OID.gost28147_ecb), 
                new ASN1.STB.GOSTSBlock(new ASN1.ObjectIdentifier(sboxOID))
            );
            // получить алгоритм шифрования
            CAPI.Cipher cipher = privateKey.Factory.
                CreateAlgorithm<CAPI.Cipher>(privateKey.Scope, parameters); 

            // проверить наличие алгоритма
            if (cipher == null) throw new NotSupportedException(); return cipher;
        }
        // создать алгоритм вычисления имитовставки
        protected Mac CreateMacAlgorithm(IPrivateKey privateKey, string sboxOID)
        {
            // закодировать параметры алгоритма
            ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.STB.OID.gost28147_mac), 
                new ASN1.STB.GOSTSBlock(new ASN1.ObjectIdentifier(sboxOID))
            );
            // получить алгоритм вычисления имитовставки
            Mac macAlgorithm = privateKey.Factory.CreateAlgorithm<Mac>(privateKey.Scope, parameters); 
        
            // проверить наличие алгоритма
            if (macAlgorithm == null) throw new NotSupportedException(); return macAlgorithm;
        }
    }
}
