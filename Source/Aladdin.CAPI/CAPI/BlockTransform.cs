using System;

namespace Aladdin.CAPI
{
    ///////////////////////////////////////////////////////////////////////////////
    // Преобразование режима шифрования 
    ///////////////////////////////////////////////////////////////////////////////
    public abstract class BlockTransform : Transform
    {
	    // функция обратного вызова
	    public BlockTransform(int blockSize)
	    
		    // сохранить переданные параметры
            { this.blockSize = blockSize; } private int blockSize;

        // размер блока алгоритма
        public override int BlockSize { get { return blockSize; } }

        // инициализировать алгоритм
	    public override void Init() {}

	    // преобразовать данные
	    public override int Update(byte[] data, int dataOff, int dataLen, byte[] buf, int bufOff)
	    {
		    // для всех полных блоков
		    for (int cb = 0; cb < dataLen; cb += BlockSize)
		    {
			    // преобразовать блок данных
			    Update(data, dataOff + cb, buf, bufOff + cb); 
            }
		    return dataLen; 
	    }
        // преобразовать блок данных
        protected abstract void Update(byte[] data, int dataOff, byte[] buf, int bufOff); 

	    // завершить преобразование
	    public override int Finish(byte[] data, int dataOff, int dataLen, byte[] buf, int bufOff)
	    {
		    // определить размер полных блоков
		    int cbBlocks = dataLen / BlockSize * BlockSize; 
		
		    // преобразовать полные блоки
		    Update(data, dataOff, cbBlocks, buf, bufOff); 

		    // перейти на неполный блок
		    dataOff += cbBlocks; bufOff += cbBlocks; dataLen -= cbBlocks;

		    // проверить наличие данных
		    if (dataLen != 0) { byte[] block = new byte[BlockSize]; 

		        // скопировать последний блок
		        Array.Copy(data, dataOff, block, 0, dataLen);

		        // зашифровать последний блок
		        Update(block, 0, BlockSize, block, 0);

		        // скопировать результат
		        Array.Copy(block, 0, buf, bufOff, dataLen);
            }
            return cbBlocks + dataLen; 
	    }
    }
}
