using System; 
using System.Diagnostics.CodeAnalysis; 

namespace Aladdin.CAPI.ANSI.Rnd
{
    ///////////////////////////////////////////////////////////////////////////////
    // Генератор случайных данных SHA1PRNG
    ///////////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
    public class SHA1PRNG : RefObject, IRand
    {
        // алгоритм хэширования и начальное состояние
        private CAPI.Hash digest; private byte[] state; 
    
        // невозвращенные данные хэширования 
        private byte[] remainder; private int remCount;
  
        // конструктор
        public static SHA1PRNG Create(object window, IRand rand)
        {
            // создать алгоритм хэширования
            using (CAPI.Hash digest = new Hash.SHA1())
            {
                // выделить буфер для случайных данных
                byte[] seed = new byte[digest.HashSize]; 
                
                // сгенерировать случайные данные
                rand.Generate(seed, 0, seed.Length);
        
                // создать генератор случайных данных
                return new SHA1PRNG(window, digest, seed); 
            }
        }
        // конструктор
        public static SHA1PRNG Create(object window, byte[] seed)
        {
            // создать алгоритм хэширования
            using (CAPI.Hash digest = new Hash.SHA1())
            {
                // создать генератор случайных данных
                return new SHA1PRNG(window, digest, seed); 
            }
        }
        // конструктор
        public SHA1PRNG(object window, CAPI.Hash digest, byte[] seed)
        {
            // сохранить алгоритм хэширования
            this.digest = RefObject.AddRef(digest); this.window = window; 
        
            // захэшировать начальные данные 
            digest.Init(); digest.Update(seed, 0, seed.Length); 
            
            // вычислить хэш-значение от начальных данных
            state = new byte[digest.HashSize]; digest.Finish(state, 0); 

            // указать отсутствие данных 
            remainder = new byte[digest.HashSize]; remCount = 0; digest.Init(); 
        }
        // деструктор
        protected override void OnDispose()
        {
            // освободить выделенные ресурсы
            RefObject.Release(digest); base.OnDispose();
        }
        // сгенерировать данные 
        public void Generate(byte[] buf, int bufOff, int bufLen)
        {
            // при наличии данных 
            int copied = 0; if (remCount > 0)
            {
                // определить число байтов из последнего хэширования 
                copied = (bufLen < remainder.Length - remCount) ? 
                    bufLen : (remainder.Length - remCount);
      
                // для всех байтов
                for (int m = 0; m < copied; m++)
                {
                    // скопировать байты
                    buf[bufOff + m] = remainder[remCount]; 
                
                    // обнулить использованный байт
                    remainder[remCount++] = 0;
                }
            }
            // пока не сгенерированы все данные 
            for (bool modified = false; copied < bufLen; modified = false)
            {
                // захэшировать состояние
                digest.Update(state, 0, state.Length);
        
                // вычислить хэш-значение
                digest.Finish(remainder, 0); digest.Init(); 
        
                // для всех разрядов
                for (int n = 0, carry = 1; n < state.Length; n++)
                {
                    // сложить разряд
                    int j = state[n] + remainder[n] + carry;

                    // проверить изменение состояния 
                    if (state[n] != (byte)j) modified = true;

                    // сохранить значение и бит переноса
                    state[n] = (byte)j; carry = j >> 8;
                }
                // явно изменить состояние
                if (!modified) state[0]++;
        
                // определить число байтов
                remCount = (bufLen - copied > remainder.Length) ? 
                    remainder.Length : (bufLen - copied);
        
                // для всех байтов 
                for (int m = 0; m < remCount; m++)
                {
                    // скопировать байты
                    buf[bufOff + copied++] = remainder[m]; remainder[m] = 0;
                }
            }
            remCount %= remainder.Length;
        } 
        // объект окна
        public object Window { get { return window; }} private object window; 
    }
}
