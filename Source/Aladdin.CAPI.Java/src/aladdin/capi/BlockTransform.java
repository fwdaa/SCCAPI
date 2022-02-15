package aladdin.capi;
import java.io.*;

///////////////////////////////////////////////////////////////////////////////
// Преобразование режима шифрования 
///////////////////////////////////////////////////////////////////////////////
public abstract class BlockTransform extends Transform
{
    // размер блока
    private final int blockSize;

    // конструктор
    public BlockTransform(int blockSize)
    {
        // сохранить переданные параметры
        this.blockSize = blockSize;
    }
    // размер блока алгоритма
    @Override public int blockSize() { return blockSize; } 

    // инициализировать алгоритм
    @Override public void init() throws IOException {} 
    
    // преобразовать данные
    @Override public int update(byte[] data, int dataOff, 
        int dataLen, byte[] buf, int bufOff) throws IOException
    {
        // для всех полных блоков
        for (int cb = 0; cb < dataLen; cb += blockSize())
        {
            // преобразовать блок данных
            update(data, dataOff + cb, buf, bufOff + cb); 
        }
        return dataLen; 
    }
    // преобразовать блок данных
    protected abstract void update(
        byte[] data, int dataOff, byte[] buf, int bufOff) throws IOException; 
    
    // завершить преобразование
    @Override public int finish(byte[] data, int dataOff, 
        int dataLen, byte[] buf, int bufOff) throws IOException
    {
        // определить размер полных блоков
        int cbBlocks = dataLen / blockSize() * blockSize(); 

        // преобразовать полные блоки
        update(data, dataOff, cbBlocks, buf, bufOff); 

        // перейти на неполный блок
        dataOff += cbBlocks; bufOff += cbBlocks; dataLen -= cbBlocks;

        // проверить наличие данных
        if (dataLen != 0) { byte[] block = new byte[blockSize()]; 

            // скопировать последний блок
            System.arraycopy(data, dataOff, block, 0, dataLen);

            // зашифровать последний блок
            update(block, 0, blockSize(), block, 0); 

            // скопировать результат
            System.arraycopy(block, 0, buf, bufOff, dataLen); 
        }
        return cbBlocks + dataLen; 
    }
}
