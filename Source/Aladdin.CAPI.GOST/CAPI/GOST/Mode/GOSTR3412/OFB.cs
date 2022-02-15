using System; 

namespace Aladdin.CAPI.GOST.Mode.GOSTR3412
{
    ///////////////////////////////////////////////////////////////////////////////
    // Режим OFB
    ///////////////////////////////////////////////////////////////////////////////
    public class OFB : CAPI.Mode.OFB
    {
        // режим смены ключа и размер смены ключа
        private KeyDerive keyMeshing; private int N; 
    
        // конструктор
	    public OFB(CAPI.Cipher engine, CipherMode.OFB parameters, 
            KeyDerive keyMeshing, int N) : base(engine, parameters)
	    { 
            // проверить корректность параметров
            if ((N % engine.BlockSize) != 0) throw new ArgumentException(); 

            // сохранить переданные параметры
            this.keyMeshing = RefObject.AddRef(keyMeshing); this.N = N; 
	    }
        // конструктор
	    public OFB(CAPI.Cipher engine, CipherMode.OFB parameters) 

            // сохранить переданные параметры
            : base(engine, parameters) { this.keyMeshing = null; N = 0; }

        // деструктор
        protected override void OnDispose() 
        { 
            // освободить ресурсы
            RefObject.Release(keyMeshing); base.OnDispose();
        }
        // преобразование зашифрования
        protected override CAPI.Transform CreateEncryption(ISecretKey key) 
        { 
            // преобразовать тип параметров
            CipherMode.OFB parameters = (CipherMode.OFB)Mode; 

            // преобразование зашифрования
            return new OFB_ENC(Engine, keyMeshing, N, key, parameters); 
        }
        // преобразование расшифрования
        protected override CAPI.Transform CreateDecryption(ISecretKey key) 
        { 
            // преобразовать тип параметров
            CipherMode.OFB parameters = (CipherMode.OFB)Mode; 

            // преобразование расшифрования
            return new OFB_ENC(Engine, keyMeshing, N, key, parameters); 
        }
    }
}