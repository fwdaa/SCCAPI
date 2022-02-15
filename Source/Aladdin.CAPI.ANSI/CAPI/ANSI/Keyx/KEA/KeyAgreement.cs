using System;
using System.IO;
using System.Diagnostics.CodeAnalysis;

namespace Aladdin.CAPI.ANSI.Keyx.KEA
{
    ///////////////////////////////////////////////////////////////////////////
    // Формирование общего ключа KEA
    ///////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
    public class KeyAgreement : RefObject, IKeyAgreement
    {
        // способ кодирования чисел
        private const Math.Endian Endian = Math.Endian.BigEndian; 

        // значение дополнения
        private static readonly byte[] pad = new byte[] {
            (byte)0x72, (byte)0xF1, (byte)0xA8, (byte)0x7E, (byte)0x92,
            (byte)0x82, (byte)0x41, (byte)0x98, (byte)0xAB, (byte)0x0B
        };
        // алгоритм шифрования блока
        private CAPI.Cipher skipjack; 
    
        // конструктор
        public KeyAgreement(CAPI.Cipher skipjack) 
        { 
            // сохранить переданные параметры
            this.skipjack = RefObject.AddRef(skipjack);
        }
        // освободить используемые ресурсы
        protected override void OnDispose() 
        {
            // освободить используемые ресурсы
            RefObject.Release(skipjack); base.OnDispose();
        }
        // наследовать ключ на стороне оправителе
        public virtual DeriveData DeriveKey(CAPI.IPrivateKey privateKey, 
            CAPI.IPublicKey publicKey, IRand rand, SecretKeyFactory keyFactory, int keySize)
        {
            // преобразовать тип параметров
            ANSI.KEA.IParameters dhParameters = (ANSI.KEA.IParameters)publicKey.Parameters; 

            // личный ключ
            ANSI.KEA.IPrivateKey dhPrivateKey = (ANSI.KEA.IPrivateKey)privateKey; 

            // открытый ключ
            ANSI.KEA.IPublicKey dhPublicKey = (ANSI.KEA.IPublicKey)publicKey; 
        
            // извлечь параметры
            Math.BigInteger p = dhParameters.P; Math.BigInteger g = dhParameters.G;

            // извлечь параметры
            Math.BigInteger q = dhParameters.Q; int bitsQ = q.BitLength; 
        
            // извлечь значения ключей
            Math.BigInteger x = dhPrivateKey.X; Math.BigInteger y = dhPublicKey.Y; 
        
            // инициализировать переменные
            Math.BigInteger r = null; Math.BigInteger w = null;
            
            // указать генератор случайных чисел
            using (Random random = new Random(rand))
            do { 
                // сгенерировать случайное число
                do { r = new Math.BigInteger(bitsQ, random); }
            
                // проверить условие генерации
                while (r.Signum == 0 || r.CompareTo(p) >= 0);

                // выполнить сложение степеней 
                w = y.ModPow(r, p).Add(y.ModPow(x, p)).Mod(p); 
            }
            while (w.Signum == 0); 

            // выполнить возведение в степень
            Math.BigInteger R = g.ModPow(r, p); 

            // получить закодированное представление числа
            byte[] encodedR = Math.Convert.FromBigInteger(R, Endian, 128); 
        
            // создать ключ
            using (ISecretKey key = CreateKey(w, keyFactory)) 
            {
                // вернуть значение ключа и нонки
                return new DeriveData(key, encodedR);  
            }
        }
        // наследовать ключ на стороне получателе
        public virtual ISecretKey DeriveKey(CAPI.IPrivateKey privateKey, 
            CAPI.IPublicKey publicKey, byte[] random, SecretKeyFactory keyFactory, int keySize) 
        {
            // преобразовать тип параметров
            ANSI.KEA.IParameters dhParameters = (ANSI.KEA.IParameters)publicKey.Parameters; 

            // личный ключ
            ANSI.KEA.IPrivateKey dhPrivateKey = (ANSI.KEA.IPrivateKey)privateKey; 

            // открытый ключ
            ANSI.KEA.IPublicKey dhPublicKey = (ANSI.KEA.IPublicKey)publicKey; 
        
            // извлечь параметры
            Math.BigInteger p = dhParameters.P; Math.BigInteger q = dhParameters.Q;
        
            // извлечь значения ключей
            Math.BigInteger x = dhPrivateKey.X; Math.BigInteger y = dhPublicKey.Y; 
        
            //  раскодировать случайное значение
            Math.BigInteger R = Math.Convert.ToBigInteger(random, Endian); 
        
            // проверить корректность значения
            if (R.Signum == 0 || R.CompareTo(p) >= 0) throw new InvalidDataException(); 
        
            // проверить корректность значения
            if (!R.ModPow(q, p).Equals(Math.BigInteger.One)) throw new InvalidDataException();

            // выполнить сложение степеней 
            Math.BigInteger w = R.ModPow(x, p).Add(y.ModPow(x, p)).Mod(p); 
        
            // проверить корректность данных и создать ключ
            if (w.Signum == 0) throw new InvalidDataException(); return CreateKey(w, keyFactory);
        }
        private ISecretKey CreateKey(Math.BigInteger w, SecretKeyFactory keyFactory)
        {
            // получить закодированное представление числа
            byte[] encodedW = Math.Convert.FromBigInteger(w, Endian, 128); 

            // создать два ключа
            byte[] v1 = Arrays.CopyOf(encodedW,  0, 10); 
            byte[] v2 = Arrays.CopyOf(encodedW, 10, 10); 
        
            // выполнить сложение с дополнением
            for (int i = 0; i < 10; i++) v1[i] ^= pad[i]; 

            // создать ключ шифрования
            using (ISecretKey key = skipjack.KeyFactory.Create(v1))
            {
                // создать алгоритм шифрования блока
                using (Transform transform = skipjack.CreateEncryption(key, PaddingMode.None))
                { 
                    // зашифровать блок
                    transform.Init(); transform.Update(v2, 0, 8, v2, 0); 
                    
                    v2[8] ^= v2[0]; v2[9] ^= v2[1];

                    // зашифровать блок
                    transform.Update(v2, 0, 8, v2, 0); return keyFactory.Create(v2); 
                }
            }
        }
    }
}