using System; 
using System.Diagnostics.CodeAnalysis; 

namespace Aladdin.CAPI
{
    ///////////////////////////////////////////////////////////////////////////////
    // Блочный алгоритм шифрования
    ///////////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
    public class BlockCipher : RefObject, IBlockCipher
    {
        // алгоритм шифрования блока
        private Cipher engine; private PaddingMode padding; 

        // конструктор
        public BlockCipher(Cipher engine) : this(engine, PaddingMode.Any) {}

        // конструктор
        public BlockCipher(Cipher engine, PaddingMode padding) 
        { 
            // сохранить переданные параметры
            this.engine = RefObject.AddRef(engine); this.padding = padding; 
        }
        // деструктор
        protected override void OnDispose() 
        { 
            // освободить ключ
            RefObject.Release(engine); base.OnDispose();
        } 
        // тип ключа
        public SecretKeyFactory KeyFactory  { get { return engine.KeyFactory; }}

        // размер ключей и блока
        public int[] KeySizes  { get { return engine.KeySizes;  }} 
        public int   BlockSize { get { return engine.BlockSize; }} 

        // блочный алгоритм шифрования
        protected Cipher Engine { get { return engine; }} 
    
        // режим дополнения 
        protected PaddingMode Padding { get { return padding; }}

        // создать режим шифрования
        public virtual Cipher CreateBlockMode(CipherMode mode)
        {
            // вернуть режим шифрования ECB
            if (mode is CipherMode.ECB) return new Mode.ECB(Engine, padding);  
            if (mode is CipherMode.CBC) 
            {
                // вернуть режим шифрования CBC
                return new Mode.CBC(Engine, (CipherMode.CBC)mode, padding);  
            }
            if (mode is CipherMode.CFB) 
            {
                // вернуть режим шифрования CFB
                return new Mode.CFB(Engine, (CipherMode.CFB)mode);  
            }
            if (mode is CipherMode.OFB) 
            {
                // вернуть режим шифрования CFB
                return new Mode.OFB(Engine, (CipherMode.OFB)mode);  
            }
            if (mode is CipherMode.CTR) 
            {
                // вернуть режим шифрования CFB
                return new Mode.CTR(Engine, (CipherMode.CTR)mode);  
            }
            // при ошибке выбросить исключение
            throw new NotSupportedException(); 
        }
    }
}
