package aladdin.capi;
import aladdin.*; 
import java.io.*; 
import java.util.*;

///////////////////////////////////////////////////////////////////////////
// Преобразование данныx
///////////////////////////////////////////////////////////////////////////
public class Transform extends RefObject implements IAlgorithm
{
	// размер блока
	public int blockSize() { return 1; } 
	// режим дополнения
    public PaddingMode padding() { return PaddingMode.NONE; } 
    
	// преобразовать данные
	public int transformData(byte[] data, 
        int dataOff, int dataLen, byte[] buf, int bufOff) throws IOException
	{
        // определить размер блока
        int blockSize = blockSize(); init(); if (dataLen > 0)
        {
            // определить число блоков данных кроме последнего
            int cb = (dataLen - 1) / blockSize * blockSize; 

            // преобразовать данные
            int total = update(data, dataOff, cb, buf, bufOff); 

            // преобразовать данные
            return total + finish(data, dataOff + cb, dataLen - cb, buf, bufOff + total);
        }
        // преобразовать данные
        else return finish(data, dataOff, dataLen, buf, bufOff); 
	}
	// преобразовать данные
	public byte[] transformData(byte[] data, int dataOff, int dataLen) throws IOException
	{
        // определить размер блока
        int blockSize = blockSize(); init(); if (dataLen > 0)
        {
            // выделить буфер для результата
            byte[] buffer = new byte[(dataLen / blockSize + 1) * blockSize];

            // определить число блоков данных кроме последнего
            int cb = (dataLen - 1) / blockSize * blockSize; 

            // преобразовать данные
            int total = update(data, dataOff, cb, buffer, 0); 

            // преобразовать данные
            total += finish(data, dataOff + cb, dataLen - cb, buffer, total); 

            // переразместить буфер
            return (total < buffer.length) ? Arrays.copyOf(buffer, total) : buffer; 
        }
        else {
            // выделить буфер для результата
            byte[] buffer = new byte[blockSize]; 
            
            // преобразовать данные
            int total = finish(data, dataOff, dataLen, buffer, 0); 

            // переразместить буфер
            return (total < buffer.length) ? Arrays.copyOf(buffer, total) : buffer; 
        }
	}
    // инициализировать алгоритм
    public void init() throws IOException {} 
    
	// преобразовать данные
	public int update(byte[] data, int dataOff, 
        int dataLen, byte[] buf, int bufOff) throws IOException
    {
        // скопировать данные
        System.arraycopy(data, dataOff, buf, bufOff, dataLen); return dataLen; 
    }
	// завершить преобразование
	public int finish(byte[] data, int dataOff, 
        int dataLen, byte[] buf, int bufOff) throws IOException
    {
        // скопировать данные
        System.arraycopy(data, dataOff, buf, bufOff, dataLen); return dataLen; 
    }
}
