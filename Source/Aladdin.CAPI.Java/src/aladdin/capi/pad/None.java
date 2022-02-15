package aladdin.capi.pad;
import aladdin.*; 
import aladdin.capi.*;

///////////////////////////////////////////////////////////////////////////////
// Отсутствие дополнения
///////////////////////////////////////////////////////////////////////////////
public class None extends BlockPadding
{ 
    // идентификатор режима
    @Override public PaddingMode mode() { return PaddingMode.NONE; } 
    
    // алгоритм зашифрования данных
    @Override public Transform createEncryption(Transform encryption, CipherMode mode)
    {
        // вызвать базовую функцию
        Transform transform = super.createEncryption(encryption, mode); 

        // алгоритм зашифрования данных
        return (transform == null) ? RefObject.addRef(encryption) : transform; 
    }
    // алгоритм расшифрования данных
    @Override public Transform createDecryption(Transform decryption, CipherMode mode)
    {
        // вызвать базовую функцию
        Transform transform = super.createDecryption(decryption, mode); 

        // алгоритм расшифрования данных
        return (transform == null) ? RefObject.addRef(decryption) : transform; 
    }
}
