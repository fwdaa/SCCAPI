using System; 

namespace Aladdin.CAPI.GOST.Mode.GOSTR3412
{
    ///////////////////////////////////////////////////////////////////////////////
    // Режим ECB
    ///////////////////////////////////////////////////////////////////////////////
    public class ECB : CAPI.Mode.ECB
    {
        // режим смены ключа и размер смены ключа
        private KeyDerive keyMeshing; private int N; 
    
        // конструктор
	    public ECB(CAPI.Cipher engine, KeyDerive keyMeshing, int N, PaddingMode padding) : base(engine, padding)
	    { 
            // проверить корректность параметров
            if ((N % engine.BlockSize) != 0) throw new ArgumentException(); 

            // сохранить переданные параметры
            this.keyMeshing = RefObject.AddRef(keyMeshing); this.N = N; 
	    }
        // конструктор
	    public ECB(CAPI.Cipher engine, KeyDerive keyMeshing, int N) 
            
            // сохранить переданные параметры
            : this(engine, keyMeshing, N, PaddingMode.Any) {}

        // конструктор
	    public ECB(CAPI.Cipher engine, PaddingMode padding) 
            
            // сохранить переданные параметры
            : base(engine, padding) { this.keyMeshing = null; N = 0; }

        // конструктор
	    public ECB(CAPI.Cipher engine) : this(engine, PaddingMode.Any) {}

        // деструктор
        protected override void OnDispose() 
        { 
            // освободить ресурсы
            RefObject.Release(keyMeshing); base.OnDispose();
        }
        // преобразование зашифрования
        protected override Transform CreateEncryption(ISecretKey key) 
        { 
            // преобразование зашифрования
            return new ECB_ENC(Engine, keyMeshing, N, key); 
        }
        // преобразование расшифрования
        protected override Transform CreateDecryption(ISecretKey key) 
        { 
            // преобразование расшифрования
            return new ECB_DEC(Engine, keyMeshing, N, key); 
        }
    }
}
