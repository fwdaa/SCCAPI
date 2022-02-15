using System;

namespace Aladdin.CAPI
{
	///////////////////////////////////////////////////////////////////////////
	// Блочный алгоритм хэширования
	///////////////////////////////////////////////////////////////////////////
	public abstract class BlockHash : Hash
	{
		// вспомогательный буфер
		private byte[] buffer; private int cbBuffer;

        // конструктор
        public BlockHash() { buffer = null; cbBuffer = 0; }

		// инициализировать алгоритм
		public override void Init() 
        { 
		    // выделить память для буфера
		    buffer = new byte[BlockSize]; cbBuffer = 0;
        }
		// захэшировать данные
		public override void Update(byte[] data, int dataOff, int dataLen)
		{
			// при наличии неполного блока
			if (dataLen == 0) return; if (cbBuffer != 0)
			{
				// при недостаточности до размера блока
				if (cbBuffer + dataLen <= BlockSize)
				{
					// сохранить входные данные
					Array.Copy(data, dataOff, buffer, cbBuffer, dataLen); 

					// изменить размер данных
					cbBuffer += dataLen; return;
				}
				// дополнить до полного блока
				Array.Copy(data, dataOff, buffer, cbBuffer, BlockSize - cbBuffer);

				// перейти на следующие данные
				dataOff += BlockSize - cbBuffer; dataLen -= BlockSize - cbBuffer;

				// обработать полный блок
				cbBuffer = BlockSize; Update(buffer, 0);
			}
			// определить размер полных блоков
			int cbBlocks = dataLen / BlockSize * BlockSize; cbBuffer = dataLen % BlockSize;

			// проверить кратность размеру блока
			if (cbBuffer == 0) { cbBuffer = BlockSize; cbBlocks -= BlockSize; }

			// для всех полных блоков
			for (int cb = 0; cb < cbBlocks; cb += BlockSize)
			{
				// скопировать полный блок
				Array.Copy(data, dataOff + cb, buffer, 0, BlockSize);

				// обработать полный блок
				Update(buffer, 0);
			}
			// скопировать неполный блок
			Array.Copy(data, dataOff + cbBlocks, buffer, 0, dataLen - cbBlocks);
		}
	    // обработать блок данных
	    protected abstract void Update(byte[] data, int dataOff);  

	    // получить хэш-значение
	    public override int Finish(byte[] buf, int bufOff)
	    {
		    // получить хэш-значение
		    Finish(buffer, 0, cbBuffer, buf, bufOff); return HashSize; 
	    }
	    // завершить преобразование
	    protected abstract void Finish(
            byte[] data, int dataOff, int dataLen, byte[] buf, int bufOff
        );
	}
}
