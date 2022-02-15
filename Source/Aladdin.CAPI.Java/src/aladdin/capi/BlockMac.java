package aladdin.capi;
import java.security.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Блочный алгоритм вычисления MAC
///////////////////////////////////////////////////////////////////////////
public abstract class BlockMac extends Mac
{
	// вспомогательный буфер
	private byte[] buffer; private int cbBuffer; 
    
    // конструктор
    public BlockMac() { buffer = null; cbBuffer = 0; }
    
	// инициализировать алгоритм
	@Override public void init(ISecretKey key) throws IOException, InvalidKeyException
    { 
		// выделить память для буфера
		buffer = new byte[blockSize()]; cbBuffer = 0;
    }
	// захэшировать данные
	@Override public void update(byte[] data, int dataOff, int dataLen) throws IOException
	{
		// при наличии неполного блока
		int blockSize = blockSize(); if (dataLen == 0) return; if (cbBuffer != 0)
		{
			// при недостаточности до размера блока
			if (cbBuffer + dataLen <= blockSize)
			{
				// сохранить входные данные
				System.arraycopy(data, dataOff, buffer, cbBuffer, dataLen); 

                // изменить размер данных
				cbBuffer += dataLen; return;
			}
			// дополнить до полного блока
			System.arraycopy(data, dataOff, buffer, cbBuffer, blockSize - cbBuffer);

			// перейти на следующие данные
			dataOff += blockSize - cbBuffer; dataLen -= blockSize - cbBuffer; 

			// обработать полный блок
			cbBuffer = blockSize; update(buffer, 0); 
		}
		// определить размер полных блоков
		int cbBlocks = dataLen / blockSize * blockSize; cbBuffer = dataLen % blockSize;

		// проверить кратность размеру блока
		if (cbBuffer == 0) { cbBuffer = blockSize; cbBlocks -= blockSize; }

        // для всех полных блоков
		for (int cb = 0; cb < cbBlocks; cb += blockSize)
		{
			// скопировать полный блок
			System.arraycopy(data, dataOff + cb, buffer, 0, blockSize);

			// обработать полный блок
			update(buffer, 0); 
        }
		// скопировать неполный блок
		System.arraycopy(data, dataOff + cbBlocks, buffer, 0, dataLen - cbBlocks);
	}
	// обработать блок данных
	protected abstract void update(byte[] data, int dataOff) throws IOException;  

	// получить хэш-значение
	@Override public int finish(byte[] buf, int bufOff) throws IOException
	{
		// получить хэш-значение
		finish(buffer, 0, cbBuffer, buf, bufOff); return macSize();
	}
	// завершить преобразование
	protected abstract void finish(byte[] data, 
        int dataOff, int dataLen, byte[] buf, int bufOff) throws IOException;
}
