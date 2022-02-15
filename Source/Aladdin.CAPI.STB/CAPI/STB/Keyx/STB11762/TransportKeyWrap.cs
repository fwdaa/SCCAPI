using System;

namespace Aladdin.CAPI.STB.Keyx.STB11762
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм согласования общего ключа на стороне отправителе
    ///////////////////////////////////////////////////////////////////////////
    public class TransportKeyWrap : CAPI.TransportKeyWrap
    {
        // способ кодирования чисел
        private const Math.Endian Endian = Math.Endian.LittleEndian; 

        private CAPI.Factory  factory;      // фабрика алгоритмов
        private SecurityStore scope;        // область видимости
        private IKeyAgreement keyAgreement; // алгоритм согласования ключа
        private String        sboxOID;      // идентификатор таблицы подстановок

        // конструктор
        public TransportKeyWrap(CAPI.Factory factory, SecurityStore scope, 
            IKeyAgreement keyAgreement, string sboxOID) 
        { 
            // сохранить переданные параметры
            this.factory      = RefObject.AddRef(factory     ); 
            this.scope        = RefObject.AddRef(scope       ); 
            this.keyAgreement = RefObject.AddRef(keyAgreement); this.sboxOID = sboxOID;
        }  
        // освободить используемые ресурсы
        protected override void OnDispose() 
        {
            // освободить используемые ресурсы
            RefObject.Release(keyAgreement); RefObject.Release(scope);
        
            // освободить используемые ресурсы
            RefObject.Release(factory); base.OnDispose();
        }
        // зашифровать ключ
        public override TransportKeyData Wrap(
            ASN1.ISO.AlgorithmIdentifier algorithmParameters, 
            IPublicKey publicKey, IRand rand, ISecretKey CEK)
        {
            // преобразовать тип параметров
            STB.STB11762.IBDHParameters bdhParameters = 
                (STB.STB11762.IBDHParameters)publicKey.Parameters; 

            // извлечь параметры алгоритма
            int L = bdhParameters.L; int N = bdhParameters.N;
        
            // проверить размер ключа
            if (N > L) throw new ArgumentException(); byte[] eCEK = new byte[32]; 
        
            // зашифровать ключ
            ASN1.STB.BDHKeyTransParams keyTransParameters = Wrap(
                publicKey, rand, CEK, eCEK, (N + 7) / 8
            ); 
            // указать параметры
            algorithmParameters = new ASN1.ISO.AlgorithmIdentifier(
                algorithmParameters.Algorithm, keyTransParameters
            ); 
            // указать параметры алгоритма
            return new TransportKeyData(algorithmParameters, eCEK); 
        }
        // зашифровать ключ
        protected virtual ASN1.STB.BDHKeyTransParams Wrap(
            IPublicKey publicKey, IRand rand, ISecretKey CEK, byte[] eCEK, int keySize)
        {
            // получить значение зашифровываемого ключа
            byte[] value = CEK.Value; if (value == null || value.Length != 32) 
            {
                // при ошибке выбросить исключение
                throw new NotSupportedException();
            } 
            // создать алгоритм шифрования
            using (CAPI.Cipher cipher = CreateCipher(sboxOID))
            {                
                // выполнить согласование ключа
                using (DeriveData kdfData = keyAgreement.DeriveKey(
                    null, publicKey, rand, cipher.KeyFactory, keySize))
                {  
                    // раскодировать значение нонки
                    Math.BigInteger V = Math.Convert.ToBigInteger(kdfData.Random, Endian); 

                    // зашифровать ключ 
                    byte[] encrypted = cipher.Encrypt(
                        kdfData.Key, PaddingMode.None, value, 0, value.Length
                    ); 
                    // скопировать зашифрованное значение
                    Array.Copy(encrypted, 0, eCEK, 0, encrypted.Length);
                
                    // создать алгоритм вычисления имитовставки
                    using (Mac macAlgorithm = CreateMacAlgorithm(sboxOID))
                    {
                        // вычислить имитовставку
                        byte[] mac = macAlgorithm.MacData(kdfData.Key, value, 0, value.Length); 

                        // вернуть использованные параметры
                        return new ASN1.STB.BDHKeyTransParams(new ASN1.Integer(V), 
                            new ASN1.OctetString(mac), new ASN1.ObjectIdentifier(sboxOID)
                        ); 
                    }
                }
            }
        }
        // создать алгоритм шифрования
        protected CAPI.Cipher CreateCipher(string sboxOID)
        {
            // закодировать параметры алгоритма
            ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.STB.OID.gost28147_ecb), 
                new ASN1.STB.GOSTSBlock(new ASN1.ObjectIdentifier(sboxOID))
            );
            // получить алгоритм шифрования
            CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, parameters); 
        
            // проверить наличие алгоритма
            if (cipher == null) throw new NotSupportedException(); return cipher;
        }
        // создать алгоритм вычисления имитовставки
        protected Mac CreateMacAlgorithm(string sboxOID)
        {
            // закодировать параметры алгоритма
            ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.STB.OID.gost28147_mac), 
                new ASN1.STB.GOSTSBlock(new ASN1.ObjectIdentifier(sboxOID))
            );
            // получить алгоритм вычисления имитовставки
            Mac macAlgorithm = factory.CreateAlgorithm<Mac>(scope, parameters); 
        
            // проверить наличие алгоритма
            if (macAlgorithm == null) throw new NotSupportedException(); return macAlgorithm;
        }
    }
}
