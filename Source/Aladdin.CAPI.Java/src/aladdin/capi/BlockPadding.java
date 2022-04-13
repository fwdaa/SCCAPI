package aladdin.capi;
import aladdin.*; 

///////////////////////////////////////////////////////////////////////////
// Режим дополнения
///////////////////////////////////////////////////////////////////////////
public abstract class BlockPadding
{ 
    // раскодировать строковое представление
    public static PaddingMode parse(String padding)
    {
        // проверить наличие строки
        if (padding == null || padding.length() == 0) return PaddingMode.ANY; 
        
        // указать используемое дополнение
        if (padding.equalsIgnoreCase("NoPadding"       )) return PaddingMode.NONE;    
        if (padding.equalsIgnoreCase("ZeroBytePadding" )) return PaddingMode.ZERO;    
        if (padding.equalsIgnoreCase("PKCS5Padding"    )) return PaddingMode.PKCS5;   
        if (padding.equalsIgnoreCase("ISO10126Padding" )) return PaddingMode.PKCS5;   
        if (padding.equalsIgnoreCase("ISO7816-4Padding")) return PaddingMode.ISO9797; 
        if (padding.equalsIgnoreCase("CTSPadding"      )) return PaddingMode.CTS;     

        // дополнение не поддерживается
        throw new UnsupportedOperationException(); 
    }
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
