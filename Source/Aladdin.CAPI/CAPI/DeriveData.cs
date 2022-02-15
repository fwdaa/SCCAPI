namespace Aladdin.CAPI
{
    public class DeriveData : RefObject
    {
        // конструктор
        public DeriveData(ISecretKey key, byte[] random) 
        { 
            // сохранить переданные параметры
            Key = RefObject.AddRef(key); Random = random;  
        }
        // освободить используемые ресурсы
        protected override void OnDispose()
        {
            // освободить используемые ресурсы
            RefObject.Release(Key); base.OnDispose();
        }
        // значение ключа и случайные данные
        public readonly ISecretKey Key; public readonly byte[] Random;  
    }
}
