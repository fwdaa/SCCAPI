using System;
using System.IO;

namespace Aladdin.CAPI.Pad
{
    ///////////////////////////////////////////////////////////////////////////////
    // Дополнение PKCS
    ///////////////////////////////////////////////////////////////////////////////
    public class PKCS5 : BlockPadding
    { 
        // идентификатор режима
        public override PaddingMode Mode { get { return PaddingMode.PKCS5; }} 

	    // алгоритм зашифрования данных
	    public override Transform CreateEncryption(Transform encryption, CipherMode mode)
        {
            // вызвать базовую функцию
            Transform transform = base.CreateEncryption(encryption, mode); 

	        // алгоритм зашифрования данных
            return (transform == null) ? new Encryption(encryption) : transform; 
        }
	    // алгоритм расшифрования данных
	    public override Transform CreateDecryption(Transform decryption, CipherMode mode)
        {
            // вызвать базовую функцию
            Transform transform = base.CreateDecryption(decryption, mode); 

	        // алгоритм расшифрования данных
            return (transform == null) ? new Decryption(decryption) : transform; 
        }
        ///////////////////////////////////////////////////////////////////////////////
        // Режим зашифрования с дополнением
        ///////////////////////////////////////////////////////////////////////////////
        public class Encryption : Transform
        {
	        private Transform encryption;	// режим зашифрования данных

	        // конструктор
	        public Encryption(Transform encryption)
            {
                // сохранить переданные параметры
                this.encryption = RefObject.AddRef(encryption); 
            }
            // освободить выделенные ресурсы
            protected override void OnDispose()
            {
                // освободить выделенные ресурсы
                RefObject.Release(encryption); base.OnDispose();
            }
            // размер блока алгоритма
	        public override int BlockSize { get { return encryption.BlockSize; }}

            // способ дополнения блока
            public override PaddingMode Padding { get { return PaddingMode.PKCS5; }}

	        // инициализировать алгоритм
	        public override void Init() { encryption.Init(); } 

	        public override int Update(byte[] data, int dataOff, int dataLen, byte[] buf, int bufOff)
	        {
		        // зашифровать полные блоки
		        encryption.Update(data, dataOff, dataLen, buf, bufOff); return dataLen; 
	        }
	        public override int Finish(
		        byte[] data, int dataOff, int dataLen, byte[] buf, int bufOff)
	        {
		        // определить размер полных блоков
		        int blockSize = BlockSize; int cbBlocks = (dataLen / blockSize) * blockSize; 

		        // преобразовать полные блоки
		        encryption.Update(data, dataOff, cbBlocks, buf, bufOff); 

		        // перейти на неполный блок
		        dataOff += cbBlocks; dataLen -= cbBlocks; bufOff += cbBlocks;

		        // скопировать исходные данные
		        Array.Copy(data, dataOff, buf, bufOff, dataLen);

		        // дополнить блок
		        for (int i = dataLen; i < blockSize; i++)
		        {
			        // установить заполнитель
			        buf[bufOff + i] = (byte)(blockSize - dataLen);
		        }
		        // зашифровать дополненный блок
		        encryption.Update(buf, bufOff, blockSize, buf, bufOff); 
		
		        // вернуть размер шифртекста
		        return cbBlocks + blockSize; 
	        }
        }
        ///////////////////////////////////////////////////////////////////////////////
        // Режим расшифрования с дополнением
        ///////////////////////////////////////////////////////////////////////////////
        public class Decryption : Transform
        {
	        private Transform decryption;		// режим расшифрования данных
	        private byte[]    lastBlock;		// последний блок данных

	        // конструктор
	        public Decryption(Transform decryption)
	        { 
		        // сохранить переданные параметры
		        this.decryption = RefObject.AddRef(decryption); lastBlock = null; 
	        }
            // освободить выделенные ресурсы
            protected override void OnDispose()
            {
                // освободить выделенные ресурсы
                RefObject.Release(decryption); base.OnDispose();
            }
            // размер блока алгоритма
	        public override int BlockSize { get { return decryption.BlockSize; }}

            // способ дополнения блока
            public override PaddingMode Padding { get { return PaddingMode.PKCS5; }}

	        // инициализировать алгоритм
	        public override void Init() { decryption.Init(); lastBlock = null; } 

	        public override int Update(byte[] data, int dataOff, int dataLen, byte[] buf, int bufOff)
	        {
		        // проверить необходимость действий
		        int blockSize = BlockSize; if (dataLen == 0) return 0; 

                // проверить корректность данных
                if ((dataLen % blockSize) != 0) throw new ArgumentException(); 

		        // определить размер полных блоков кроме последнего
		        int cbBlocks = ((dataLen - 1) / blockSize) * blockSize;

		        // при наличии последнего блока
		        if (lastBlock != null) 
		        {
			        // скопировать расшифрованный последний блок
			        Array.Copy(lastBlock, 0, buf, bufOff, blockSize); bufOff += blockSize;  

			        // расшифровать полные блоки кроме последнего
			        decryption.Update(data, dataOff, cbBlocks, buf, bufOff);

			        // сохранить последний блок
			        Array.Copy(data, dataOff + cbBlocks, lastBlock, 0, blockSize); 
			
			        // расшифровать последний блок
			        decryption.Update(lastBlock, 0, lastBlock.Length, lastBlock, 0); return dataLen; 
		        }
		        else {
			        // расшифровать полные блоки кроме последнего
			        decryption.Update(data, dataOff, cbBlocks, buf, bufOff);

			        // выделить память для последнего блока
			        lastBlock = new byte[blockSize]; 

			        // сохранить последний блок
			        Array.Copy(data, dataOff + cbBlocks, lastBlock, 0, blockSize); 
			
			        // расшифровать последний блок
			        decryption.Update(lastBlock, 0, lastBlock.Length, lastBlock, 0); return cbBlocks; 
		        }
	        }
	        public override int Finish(
		        byte[] data, int dataOff, int dataLen, byte[] buf, int bufOff)
	        {
		        // проверить корректность данных
		        if (dataLen == 0 && lastBlock == null) throw new InvalidDataException(); 

		        // проверить корректность данных
		        int blockSize = BlockSize; if ((dataLen % blockSize) != 0) 
                {
			        // при ошибке выбросить исключение
                    throw new InvalidDataException();
                }
		        // расшифровать данные
		        int total = Update(data, dataOff, dataLen, buf, bufOff); 

		        // проверить размер дополнения
		        if (lastBlock[blockSize - 1] == 0 || lastBlock[blockSize - 1] > blockSize) 
		        {
			        // при ошибке выбросить исключение
			        throw new InvalidDataException();
		        }
		        // определить размер исходного блока
		        int cb = blockSize - lastBlock[blockSize - 1];

		        // скопировать неполный блок
		        Array.Copy(lastBlock, 0, buf, bufOff + total, cb); return total + cb;
	        }
        }
    }
}
