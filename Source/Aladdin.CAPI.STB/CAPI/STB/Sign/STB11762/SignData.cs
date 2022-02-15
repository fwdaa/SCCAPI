using System;

namespace Aladdin.CAPI.STB.Sign.STB11762
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм выработки подписи данных СТБ 1176.2
    ///////////////////////////////////////////////////////////////////////////
    public class SignData : CAPI.SignData
    {
        // способ кодирования чисел
        private const Math.Endian Endian = Math.Endian.LittleEndian; 

        // алгоритм хэширования и секретный параметр
        private CAPI.Hash hashAlgorithm; private Math.BigInteger K;

        // конструктор
        public SignData() { hashAlgorithm = null; K = null; }

        // освободить используемые ресурсы
        protected override void OnDispose()
        {
            // освободить используемые ресурсы
            RefObject.Release(hashAlgorithm); base.OnDispose(); 
        }
        // инициализировать алгоритм
        public override void Init(IPrivateKey privateKey, IRand rand) 
        {
            // освободить используемые ресурсы
            RefObject.Release(hashAlgorithm); hashAlgorithm = null; 

            // преобразовать тип ключа
            STB.STB11762.IBDSPrivateKey stbPrivateKey = 
                (STB.STB11762.IBDSPrivateKey)privateKey;

            // преобразовать тип параметров
            STB.STB11762.IBDSParameters parameters = 
                (STB.STB11762.IBDSParameters)privateKey.Parameters; 

            // прочитать параметры алгоритма
            Math.BigInteger P = parameters.P; Math.BigInteger Q = parameters.Q;
            Math.BigInteger A = parameters.G; int             R = parameters.R;
            
            // вызвать базовую функцию
            base.Init(privateKey, rand); K = Math.BigInteger.Zero; 

            // указать генератор случайных чисел
            using (Random random = new Random(rand))
            do {             
                // сгенерировать число 0 < K < Q
                K = new Math.BigInteger(R, random);
            }
            // проверить выполнение требуемых условий
            while (K.Signum == 0 || K.CompareTo(Q) >= 0); 

            // вычислить T = A^(K)
            Math.BigInteger T = (new Math.Fp.MontGroup(P)).Power(A, K);

            // закодировать число T
            byte[] encodedT = Math.Convert.FromBigInteger(T, Endian);  

            // создать алгоритм хэширования
            hashAlgorithm = CreateHashAlgorithm(privateKey, parameters.H); 

            // прохэшировать число T
            hashAlgorithm.Init(); hashAlgorithm.Update(encodedT, 0, encodedT.Length); 
        }
        // обработать данные
        public override void Update(byte[] data, int dataOff, int dataLen)
        {
            // прохэшировать данные
            hashAlgorithm.Update(data, dataOff, dataLen); 
        }
        // получить подпись данных
        public override byte[] Finish(IRand rand)
        {
            // преобразовать тип ключа
            STB.STB11762.IBDSPrivateKey stbPrivateKey = 
                (STB.STB11762.IBDSPrivateKey)PrivateKey;

            // преобразовать тип параметров
            STB.STB11762.IBDSParameters parameters = 
                (STB.STB11762.IBDSParameters)PrivateKey.Parameters; 

            // прочитать параметры алгоритма
            Math.BigInteger Q = parameters.Q; int R = parameters.R;

            // получить хэш-значение
            byte[] H = new byte[32]; hashAlgorithm.Finish(H, 0);

            // обнулить незначащие биты
            if (((R - 1) % 8) != 0) H[(R - 1) / 8] &= (byte)((1 << ((R - 1) % 8)) - 1);

            // преобразовать хэш-значение в число U
            Math.BigInteger U = Math.Convert.ToBigInteger(H, 0, (R + 6) / 8, Endian);

            // выполнить вычисления
            Math.BigInteger XU = stbPrivateKey.X.Multiply(U).Mod(Q);

            // вычислить число V
            Math.BigInteger V = (K.CompareTo(XU) > 0) ? K.Subtract(XU) : K.Add(Q).Subtract(XU);

            // освободить используемые ресурсы
            RefObject.Release(hashAlgorithm); hashAlgorithm = null;  

            // проверить корректность
            if (U.Signum == 0 || V.Signum == 0) throw new InvalidOperationException();

            // выполнить конкатенацию 
            Math.BigInteger UV = U.ShiftLeft(R).Add(V); 

            // вычислить подпись
            byte[] signature = Math.Convert.FromBigInteger(UV, Endian, (R + 3) / 4); 

            // вернуть вычисленную подпись
            base.Finish(rand); return signature; 
        }
        // создать алгоритм хэширования
        protected CAPI.Hash CreateHashAlgorithm(IPrivateKey privateKey, byte[] start) 
        { 
            // создать алгоритм хэширования
            return new Hash.STB11761(start);     
        }
    }
}
