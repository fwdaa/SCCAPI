using System;
using System.IO;

namespace Aladdin.CAPI.ANSI.Wrap
{
    ///////////////////////////////////////////////////////////////////////////
    // Шифрование ключа S/MIME
    ///////////////////////////////////////////////////////////////////////////
    public class SMIME : KeyWrap
    {
        // блочный алгоритм шифрования и его CBC-режим
	    private IBlockCipher blockCipher; private CAPI.Cipher modeCBC; 
 
	    // конструктор 
	    public SMIME(IBlockCipher blockCipher, byte[] iv) 
        {
            // указать режим алгоритма
            CipherMode cipherMode = new CipherMode.CBC(iv); 
        
            // создать режим шифрования
            modeCBC = blockCipher.CreateBlockMode(cipherMode); 

            // сохранить переданные параметры
            this.blockCipher = RefObject.AddRef(blockCipher); 
        }
        // освободить выделенные ресурсы
        protected override void OnDispose()
        {
            // освободить выделенные ресурсы
            RefObject.Release(modeCBC); RefObject.Release(blockCipher); base.OnDispose();
        }
        // тип ключа
        public override SecretKeyFactory KeyFactory  { get { return modeCBC.KeyFactory; }}
        // размер ключей
	    public override int[] KeySizes { get { return modeCBC.KeySizes; }}

	    // зашифровать ключ
	    public override byte[] Wrap(IRand rand, ISecretKey key, ISecretKey wrappedKey)
	    {
		    // проверить тип ключа
		    byte[] CEK = wrappedKey.Value; if (CEK == null)
		    {
			    // при ошибке выбросить исключение
			    throw new InvalidKeyException();
		    }
		    // определить размер блока алгоритма шифрования
		    int blockSize = modeCBC.BlockSize; if (CEK.Length < 3) 
		    {
			    // при ошибке выбросить исключение
			    throw new InvalidKeyException();
		    }
		    // определить размер зашифровываемых данных
		    int length = (4 + CEK.Length + blockSize - 1) / blockSize * blockSize; 

		    // проверить наличие по крайней мере двух блоков
		    byte[] wrappedCEK = new byte[(length == blockSize) ? length + blockSize : length];  

		    // записать контрольные данные
		    wrappedCEK[0] = (byte) CEK.Length;	wrappedCEK[1] = (byte)~CEK[0]; 
		    wrappedCEK[2] = (byte)~CEK[1];		wrappedCEK[3] = (byte)~CEK[2];
 
		    // скопировать ключ шифрования данных
		    Array.Copy(CEK, 0, wrappedCEK, 4, CEK.Length); 

		    // сгенерировать случайное дополнение
		    rand.Generate(wrappedCEK, 4 + CEK.Length, wrappedCEK.Length - 4 - CEK.Length); 

		    // создать режим зашифрования CBC
		    using (Transform encryption = modeCBC.CreateEncryption(key, PaddingMode.None))
            { 
                // зашифровать сформированные данные
                encryption.Init(); encryption.Update(wrappedCEK, 0, wrappedCEK.Length, wrappedCEK, 0); 

                // повторно зашифровать сформированные данные
                encryption.Finish(wrappedCEK, 0, wrappedCEK.Length, wrappedCEK, 0); return wrappedCEK;
            } 
	    }
	    // расшифровать ключ
	    public override ISecretKey Unwrap(ISecretKey key, byte[] wrappedCEK, SecretKeyFactory keyFactory) 
	    {
		    // определить размер блока
		    int blockSize = modeCBC.BlockSize; byte[] start = new byte[blockSize];  
        
		    // проверить размер зашифрованных данных
		    if ((wrappedCEK.Length % blockSize) != 0) throw new InvalidDataException();
            
		    // проверить размер зашифрованных данных
            if (wrappedCEK.Length < blockSize * 2) throw new InvalidDataException();
        
		    // получить алгоритм шифрования блока
		    wrappedCEK = (byte[])wrappedCEK.Clone(); 

		    // извлечь предпоследний блок
		    Array.Copy(wrappedCEK, wrappedCEK.Length - 2 * blockSize, start, 0, blockSize);
 
            // создать режим CBC
		    using (CAPI.Cipher mode = blockCipher.CreateBlockMode(new CipherMode.CBC(start)))
            { 
                // расшифровать данные последнего блока
                mode.Decrypt(key, PaddingMode.None, wrappedCEK, wrappedCEK.Length - blockSize, 
                    blockSize, wrappedCEK, wrappedCEK.Length - blockSize
                );
            }
		    // использовать последний блок в качестве синхропосылки
		    Array.Copy(wrappedCEK, wrappedCEK.Length - blockSize, start, 0, blockSize); 

            // создать режим CBC
		    using (CAPI.Cipher mode = blockCipher.CreateBlockMode(new CipherMode.CBC(start)))
            { 
                // расшифровать данные, кроме последнего блока
                mode.Decrypt(key, PaddingMode.None, wrappedCEK, 
                    0, wrappedCEK.Length - blockSize, wrappedCEK, 0
                );
            }
		    // создать режим расшифрования CBC
		    using (Transform decryption = modeCBC.CreateDecryption(key, PaddingMode.None))
            { 
		        // расшифровать данные при втором проходе
		        decryption.Init(); decryption.Finish(wrappedCEK, 0, wrappedCEK.Length, wrappedCEK, 0); 
            }
		    // проверить размер ключа шифрования данных
		    if (wrappedCEK[0] < 3 || wrappedCEK[0] > wrappedCEK.Length - 4) 
		    {
			    // при ошибке выбросить исключение
			    throw new InvalidDataException();
		    }
		    // проверить контрольные данные
		    if (wrappedCEK[1] != (byte)~wrappedCEK[4]) throw new IOException();
		    if (wrappedCEK[2] != (byte)~wrappedCEK[5]) throw new IOException();
		    if (wrappedCEK[3] != (byte)~wrappedCEK[6]) throw new IOException();

		    // выделить память для расшифрованного ключа
		    byte[] CEK = new byte [wrappedCEK[0]]; 
			
		    // вернуть расшифрованный ключ
		    Array.Copy(wrappedCEK, 4, CEK, 0, CEK.Length); return keyFactory.Create(CEK);  
	    }
    }
}
