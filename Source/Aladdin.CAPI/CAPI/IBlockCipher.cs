namespace Aladdin.CAPI
{
    ///////////////////////////////////////////////////////////////////////////
    // Блочный алгоритм шифрования
    ///////////////////////////////////////////////////////////////////////////
    public interface IBlockCipher : IAlgorithm
    {
        // тип ключа, размер ключей и блока
        SecretKeyFactory KeyFactory { get; } int BlockSize { get; } 

        // создать режим шифрования
	    Cipher CreateBlockMode(CipherMode mode);
    }
}
