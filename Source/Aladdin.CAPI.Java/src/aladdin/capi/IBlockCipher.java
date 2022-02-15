package aladdin.capi;
import java.io.*;  

///////////////////////////////////////////////////////////////////////////////
// Блочный алгоритм шифрования
///////////////////////////////////////////////////////////////////////////////
public interface IBlockCipher extends IAlgorithm
{
   // тип ключа, размер ключей и размер блока
	SecretKeyFactory keyFactory(); int[] keySizes(); int blockSize(); 
    
    // создать режим шифрования
	Cipher createBlockMode(CipherMode mode) throws IOException;
}
