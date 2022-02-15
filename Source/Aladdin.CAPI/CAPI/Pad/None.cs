using System;

namespace Aladdin.CAPI.Pad
{
    ///////////////////////////////////////////////////////////////////////////////
    // Отсутствие дополнения
    ///////////////////////////////////////////////////////////////////////////////
    public class None : BlockPadding
    { 
        // идентификатор режима
        public override PaddingMode Mode { get { return PaddingMode.None; }} 

	    // алгоритм зашифрования данных
	    public override Transform CreateEncryption(Transform encryption, CipherMode mode)
        {
            // вызвать базовую функцию
            Transform transform = base.CreateEncryption(encryption, mode); 

	        // алгоритм зашифрования данных
            return (transform == null) ? RefObject.AddRef(encryption) : transform; 
        }
	    // алгоритм расшифрования данных
	    public override Transform CreateDecryption(Transform decryption, CipherMode mode)
        {
            // вызвать базовую функцию
            Transform transform = base.CreateDecryption(decryption, mode); 

	        // алгоритм расшифрования данных
            return (transform == null) ? RefObject.AddRef(decryption) : transform; 
        }
    }
}
