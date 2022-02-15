using System; 

namespace Aladdin.CAPI.STB.Sign.STB11762
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм проверки подписи данных СТБ 1176.2
    ///////////////////////////////////////////////////////////////////////////
    public class VerifyData : CAPI.VerifyData
    {
        // способ кодирования чисел
        private const Math.Endian Endian = Math.Endian.LittleEndian; 

        // алгоритм хэширования и хэш-значение
        private CAPI.Hash hashAlgorithm; private byte[] hash;           

        // конструктор
        public VerifyData() { hashAlgorithm = null; hash = null; }

        // освободить используемые ресурсы
        protected override void OnDispose()
        {
            // освободить используемые ресурсы
            RefObject.Release(hashAlgorithm); base.OnDispose(); 
        }
        // инициализировать алгоритм
        public override void Init(IPublicKey publicKey, byte[] signature)
        {
            // освободить используемые ресурсы
            RefObject.Release(hashAlgorithm); hashAlgorithm = null; 

            // преобразовать тип ключа
            STB.STB11762.IBDSPublicKey stbPublicKey = 
                (STB.STB11762.IBDSPublicKey)publicKey; 

            // преобразовать тип параметров
            STB.STB11762.IBDSParameters parameters = 
                (STB.STB11762.IBDSParameters)publicKey.Parameters; 

            // прочитать параметры алгоритма
            Math.BigInteger P = parameters.P; Math.BigInteger A = parameters.G; 
            
            // вызвать базовую функцию
            base.Init(publicKey, signature); int R = parameters.R;

            // раскодировать значение подписи
            Math.BigInteger UV = Math.Convert.ToBigInteger(signature, Endian); 
        
            // извлечь параметр U
            Math.BigInteger U = UV.ShiftRight(R);

            // вычислить параметр V
            Math.BigInteger V = UV.Subtract(U.ShiftLeft(R)); 

            // проверить корректность U и V
            if (U.Signum == 0 || V.Signum == 0 || V.BitLength > R) 
            {
                // при ошибке выбросить исключение
                throw new SignatureException();
            }
            // извлечь хэш-значение
            hash = Math.Convert.FromBigInteger(U, Endian, (R + 6) / 8);
        
            // вычислить T = A^(V) * Y^(U)
            Math.BigInteger T = (new Math.Fp.MontGroup(P)).PowerProduct(A, V, stbPublicKey.Y, U);

            // закодировать число T
            byte[] encodedT = Math.Convert.FromBigInteger(T, Endian);

            // создать алгоритм хэширования
            hashAlgorithm = CreateHashAlgorithm(publicKey, parameters.H); 

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
        public override void Finish() 
        {
            // преобразовать тип параметров
            STB.STB11762.IBDSParameters parameters = 
                (STB.STB11762.IBDSParameters)PublicKey.Parameters; 

            // прочитать параметры алгоритма
            byte[] H = new byte[32]; int R = parameters.R; 

            // получить хэш-значение
            hashAlgorithm.Finish(H, 0); if (((R - 1) % 8) != 0)
            {
                // обнулить незначащие биты
                H[(R - 1) / 8] &= (byte)((1 << ((R - 1) % 8)) - 1);
            }
            // освободить используемые ресурсы
            RefObject.Release(hashAlgorithm); hashAlgorithm = null;

            // проверить совпадение хэш-значений
            if (!Arrays.Equals(hash, 0, H, 0, (R + 6) / 8))
            {
                // при ошибке выбросить исключение
                throw new SignatureException(); 
            }
        }
        // создать алгоритм хэширования
        protected CAPI.Hash CreateHashAlgorithm(IPublicKey publicKey, byte[] start) 
        { 
            // создать алгоритм хэширования
            return new Hash.STB11761(start);     
        }
    }
}
