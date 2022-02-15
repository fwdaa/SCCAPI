using System; 
using System.Diagnostics.CodeAnalysis;

namespace Aladdin.CAPI.GOST.Cipher
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм шифрования GOST28147-89
    ///////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
    public class GOST28147 : RefObject, IBlockCipher
    {
        // алгоритм шифрования блока и режим смены ключа
        private CAPI.Cipher engine; private KeyDerive keyMeshing;
    
        // конструктор
	    public GOST28147(CAPI.Cipher engine, KeyDerive keyMeshing)  
        {
		    // сохранить переданные параметры
            this.engine = RefObject.AddRef(engine); 
        
            // указать способ смены ключа
            this.keyMeshing = RefObject.AddRef(keyMeshing); 
        } 
        // конструктор
	    public GOST28147(CAPI.Cipher engine)  
        {
		    // сохранить переданные параметры
            this.engine = RefObject.AddRef(engine); keyMeshing = null;
        }
        // освободить ресурсы
        protected override void OnDispose() 
        { 
            // освободить ресурсы
            RefObject.Release(keyMeshing); RefObject.Release(engine); base.OnDispose();
        }
        // тип ключа
        public SecretKeyFactory KeyFactory { get { return engine.KeyFactory; }}

        // размер ключей и блока
        public int[] KeySizes  { get { return engine.KeySizes ; }} 
	    public int   BlockSize { get { return engine.BlockSize; }} 
    
        // создать режим шифрования
        public CAPI.Cipher CreateBlockMode(CipherMode mode)  
        {
            if (mode is CipherMode.ECB) 
            {
                // вернуть режим шифрования ECB
                return new Mode.GOST28147.ECB(engine, keyMeshing, PaddingMode.Any);  
            }
            if (mode is CipherMode.CBC) 
            {
                // вернуть режим шифрования CBC
                return new Mode.GOST28147.CBC(
                    engine, (CipherMode.CBC)mode, keyMeshing, PaddingMode.Any
                 );  
            }
            if (mode is CipherMode.CFB) 
            {
                // вернуть режим шифрования CFB
                return new Mode.GOST28147.CFB(engine, (CipherMode.CFB)mode, keyMeshing);  
            }
            if (mode is CipherMode.CTR) 
            {
                // вернуть режим шифрования CFB
                return new Mode.GOST28147.CTR(engine, (CipherMode.CTR)mode, keyMeshing);  
            }
            // при ошибке выбросить исключение
            throw new NotSupportedException(); 
        }
    }
}

