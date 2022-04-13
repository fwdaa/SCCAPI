using System; 

namespace Aladdin.CAPI
{
    ///////////////////////////////////////////////////////////////////////////
	// Режим дополнения
    ///////////////////////////////////////////////////////////////////////////
	public abstract class BlockPadding 
    { 
        // раскодировать строковое представление
        public static PaddingMode Parse(string padding)
        {
            // проверить наличие строки
            if (String.IsNullOrEmpty(padding)) return PaddingMode.Any; 

            // указать используемое дополнение
            if (String.Compare(padding, "NoPadding"       ) == 0) return PaddingMode.None;
            if (String.Compare(padding, "ZeroBytePadding" ) == 0) return PaddingMode.Zero;
            if (String.Compare(padding, "PKCS5Padding"    ) == 0) return PaddingMode.PKCS5;
            if (String.Compare(padding, "ISO10126Padding" ) == 0) return PaddingMode.PKCS5;
            if (String.Compare(padding, "ISO7816-4Padding") == 0) return PaddingMode.ISO9797;
            if (String.Compare(padding, "CTSPadding"      ) == 0) return PaddingMode.CTS;    

            // дополнение не поддерживается
            throw new NotSupportedException();
        }
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
