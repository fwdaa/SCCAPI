namespace Aladdin.CAPI
{
    ///////////////////////////////////////////////////////////////////////////
    // Генератор случайных данных
    ///////////////////////////////////////////////////////////////////////////
#if (NET40_OR_GREATER || NETSTANDARD || NETCOREAPP)
    public sealed class RandomNumberGenerator : System.Security.Cryptography.RandomNumberGenerator
    {
        // освободить выделенные ресурсы
        protected override void Dispose(bool disposing) 
        { 
            // освободить выделенные ресурсы
            RefObject.Release(rand); base.Dispose(disposing); 
        } 
#else
    public sealed class RandomNumberGenerator : System.Security.Cryptography.RandomNumberGenerator, IDisposable
    {
        // освободить выделенные ресурсы
        public void Dispose() { RefObject.Release(rand); } 
#endif 
        // конструктор
        public RandomNumberGenerator(IRand rand) 
            
            // сохранить переданные параметры
            { this.rand = RefObject.AddRef(rand); } private IRand rand;

        // сгенерировать данные
        public override void GetBytes(byte[] data) { rand.Generate(data, 0, data.Length); }

        // сгенерировать ненулевые данные
        public override void GetNonZeroBytes(byte[] data)
        {
            // сгенерировать данные
            rand.Generate(data, 0, data.Length);
            
            // для всех значений 
            for (int i = 0; i < data.Length; i++)
            {
                // проверить отсутствие нулевых значений
                while (data[i] == 0) rand.Generate(data, i, 1); 
            }
        }
    }
}
