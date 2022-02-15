package aladdin.capi;
import aladdin.*; 

///////////////////////////////////////////////////////////////////////////
// Режим дополнения
///////////////////////////////////////////////////////////////////////////
public abstract class BlockPadding
{ 
    // идентификатор режима
    public abstract PaddingMode mode(); 
    
	// алгоритм зашифрования данных
	public Transform createEncryption(Transform encryption, CipherMode mode)
    {
        // проверить необходимость установки режима
        if (encryption.padding() == mode()) return RefObject.addRef(encryption); 

        // проверить корректность режима
        if (encryption.padding() != PaddingMode.NONE) throw new IllegalStateException();
        
        return null; 
    }
	// алгоритм расшифрования данных
	public Transform createDecryption(Transform decryption, CipherMode mode)
    {
        // проверить необходимость установки режима
         if (decryption.padding() == mode()) return RefObject.addRef(decryption); 

        // проверить корректность режима
        if (decryption.padding() != PaddingMode.NONE) throw new IllegalStateException();
        
        return null; 
    }
}
