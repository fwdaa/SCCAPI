using System; 

namespace Aladdin.CAPI
{
    ///////////////////////////////////////////////////////////////////////////
	// Режим дополнения
    ///////////////////////////////////////////////////////////////////////////
	public abstract class BlockPadding 
    { 
        // идентификатор режима
        public abstract PaddingMode Mode { get; } 

	    // алгоритм зашифрования данных
	    public virtual Transform CreateEncryption(Transform encryption, CipherMode mode)
        {
            // проверить необходимость установки режима
            if (encryption.Padding == Mode) return RefObject.AddRef(encryption); 

            // проверить корректность режима
            if (encryption.Padding != PaddingMode.None) throw new InvalidOperationException();

            return null; 
        }
	    // алгоритм расшифрования данных
	    public virtual Transform CreateDecryption(Transform decryption, CipherMode mode)
        {
            // проверить необходимость установки режима
            if (decryption.Padding == Mode) return RefObject.AddRef(decryption); 

            // проверить корректность режима
            if (decryption.Padding != PaddingMode.None) throw new InvalidOperationException();

            return null; 
        }
    }
}
