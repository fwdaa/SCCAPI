using System;

namespace Aladdin.CAPI.PBE
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм шифрования по паролю PBES1 с использованием режима CBC
    ///////////////////////////////////////////////////////////////////////////
    public class PBES1CBC : PBES1
    {
        // блочный алгоритм шифрования и размер ключа
        private IBlockCipher blockCipher; private int keyLength; 
    
	    // конструктор 
	    public PBES1CBC(IBlockCipher blockCipher, int keyLength, 
            Hash hashAlgorithm, byte[] salt, int iterations)

            // сохранить переданные параметры			
            : base(hashAlgorithm, salt, iterations, blockCipher.KeyFactory)
        {
            // сохранить переданные параметры	
            this.blockCipher = RefObject.AddRef(blockCipher); this.keyLength = keyLength;
        } 
        // освободить выделенные ресурсы
        protected override void OnDispose()
        {
            // освободить выделенные ресурсы
            RefObject.Release(blockCipher); base.OnDispose();
        }
        // создать алгоритм шифрования
	    protected override Cipher CreateCipher(byte[] iv)
	    {
            // указать параметры режима
            CipherMode mode = new CipherMode.CBC(iv); 
        
            // получить алгоритм шифрования
            Cipher cipher = blockCipher.CreateBlockMode(mode); 
        
            // проверить наличие алгоритма
            if (cipher == null) throw new NotSupportedException(); return cipher;  
	    }
	    // размер ключа и вектора инициализации
	    protected override int KeyLength { get { return keyLength;             }} 
	    protected override int IVLength  { get { return blockCipher.BlockSize; }}
    }
}
