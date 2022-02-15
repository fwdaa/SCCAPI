using System;
using System.Diagnostics.CodeAnalysis;

namespace Aladdin.CAPI.STB.Keyx.STB11762
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм согласования общего ключа
    ///////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
    public class KeyAgreement : RefObject, IKeyAgreement
    {
        // способ кодирования чисел
        private const Math.Endian Endian = Math.Endian.LittleEndian; 

        // наследовать ключ на стороне оправителе
        public virtual DeriveData DeriveKey(IPrivateKey privateKey, 
            IPublicKey publicKey, IRand rand, SecretKeyFactory keyFactory, int keySize)
        {
            // преобразовать тип параметров
            STB.STB11762.IBDHParameters bdhParameters = 
                (STB.STB11762.IBDHParameters)publicKey.Parameters; 

            // открытый ключ
            STB.STB11762.IBDHPublicKey bdhPublicKey = 
                (STB.STB11762.IBDHPublicKey)publicKey; 

            // извлечь параметры алгоритма
            int N = bdhParameters.N; Math.BigInteger P = bdhParameters.P;
            int R = bdhParameters.R; Math.BigInteger G = bdhParameters.G;

            // указать значение числа Y
            Math.BigInteger Y = bdhPublicKey.Y; Math.BigInteger K = null; 

            // указать генератор случайных чисел
            using (Random random = new Random(rand))
            { 
                // сгенерировать случайное число K
                K = new Math.BigInteger(R, random); 
            }
            // указать группу Монтгомери
            Math.GroupMul<Math.BigInteger> group = new Math.Fp.MontGroup(P); 

            // вычислить U = Y^(K) (mod P) и V = G^(K) (mod P)
            Math.BigInteger U = group.Power(Y, K); Math.BigInteger V = group.Power(G, K);

            // получить закодированные значения U и V
            byte[] encodedU = Math.Convert.FromBigInteger(U, Endian);  
            byte[] encodedV = Math.Convert.FromBigInteger(V, Endian);  

            // выделить память для ключа
            byte[] key = new byte[(N + 7) / 8]; 
        
            // в зависимости от размера ключа
            if (key.Length > encodedU.Length)
            {
                // скопировать значение ключа
                Array.Copy(encodedU, 0, key, 0, encodedU.Length);
            
                // обнулить неиспользуемые данные
                for (int i = encodedU.Length; i < key.Length; i++) key[i] = 0; 
            }
            else {
                // скопировать значение ключа
                Array.Copy(encodedU, 0, key, 0, key.Length);

                // выделить нужное число бит
                if ((N % 8) > 0) key[N / 8] &= (byte)((1 << (N % 8)) - 1); 
            }
            // вернуть значение ключа и нонки
            using (ISecretKey k = keyFactory.Create(key)) return new DeriveData(k, encodedV); 
        }
        // наследовать ключ на стороне получателе
        public virtual ISecretKey DeriveKey(IPrivateKey privateKey, 
            IPublicKey publicKey, byte[] random, SecretKeyFactory keyFactory, int keySize)
        {
            // преобразовать тип личного ключа
            STB.STB11762.IBDHPrivateKey bdhPrivateKey = 
                (STB.STB11762.IBDHPrivateKey)privateKey;
        
            // преобразовать тип параметров
            STB.STB11762.IBDHParameters bdhParameters = 
                (STB.STB11762.IBDHParameters)privateKey.Parameters; 

            // извлечь параметры алгоритма
            int N = bdhParameters.N; Math.BigInteger P = bdhParameters.P;

            // прочитать большое число V
            Math.BigInteger V = Math.Convert.ToBigInteger(random, Endian); 
        
            // вычислить V^(X) (mod P)
            Math.BigInteger U = (new Math.Fp.MontGroup(P)).Power(V, bdhPrivateKey.X);

            // получить закодированное значение ключа
            byte[] encodedU = Math.Convert.FromBigInteger(U, Endian);  

            // выделить память для ключа
            byte[] key = new byte[(N + 7) / 8]; 
        
            // в зависимости от размера ключа
            if (key.Length > encodedU.Length)
            {
                // скопировать значение ключа
                Array.Copy(encodedU, 0, key, 0, encodedU.Length);
            
                // обнулить неиспользуемые данные
                for (int i = encodedU.Length; i < key.Length; i++) key[i] = 0; 
            }
            else {
                // скопировать значение ключа
                Array.Copy(encodedU, 0, key, 0, key.Length);

                // выделить нужное число бит
                if ((N % 8) > 0) key[N / 8] &= (byte)((1 << (N % 8)) - 1); 
            }
            // вернуть созданные ключ
            return keyFactory.Create(key); 
        }
    }
}
