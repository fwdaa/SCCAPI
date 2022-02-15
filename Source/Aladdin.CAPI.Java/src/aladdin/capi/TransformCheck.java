package aladdin.capi;
import aladdin.*;
import aladdin.asn1.iso.*; 
import aladdin.util.*;
import java.io.*; 
import java.util.*;

///////////////////////////////////////////////////////////////////////////
// Преобразование данныx с дополнительным контролем целостности
///////////////////////////////////////////////////////////////////////////
public class TransformCheck extends Transform
{
    // преобразование и алгоритм вычисления контрольной суммы
    private final Transform transform; private final Hash hashAlgorithm;
    // признак зашифрования
    private final boolean encrypt; 
        
    public TransformCheck(Transform transform, Hash hashAlgorithm, boolean encrypt)
    {
        // проверить корректность размера блока
        if ((transform.blockSize() % hashAlgorithm.blockSize()) != 0)
        {
            // при ошибке выбросить исключение
            throw new IllegalStateException(); 
        }
        // сохранить переданные параметры
        this.transform = RefObject.addRef(transform); this.encrypt = encrypt; 

        // сохранить переданные параметры
        this.hashAlgorithm = RefObject.addRef(hashAlgorithm); 
    }
    // освободить выделенные ресурсы
    @Override protected void onClose() throws IOException
    { 
        // освободить выделенные ресурсы
        RefObject.release(hashAlgorithm); 

        // освободить выделенные ресурсы
        RefObject.release(transform); super.onClose();         
    } 
    // преобразование 
    protected final Transform transform() { return transform; } 
    // алгоритм вычисления контрольной суммы
    protected final Hash hashAlgorithm() { return hashAlgorithm; }
    
	// размер блока
	@Override public int blockSize() { return transform.blockSize(); } 
	// режим дополнения
    @Override public PaddingMode padding() { return transform.padding(); } 
    
	// размер контрольной суммы
	public final int checkSize() { return hashAlgorithm.hashSize(); } 
    
	// преобразовать данные
	@Override public final int transformData(byte[] data, int dataOff, 
        int dataLen, byte[] buf, int bufOff) throws IOException
    {
        // создать пустой список атрибутов
        List<Attribute> attributes = new ArrayList<Attribute>(); 
        
        // преобразовать данные
        return transformData(data, dataOff, dataLen, buf, bufOff, attributes); 
    }
	// преобразовать данные
	public int transformData(byte[] data, int dataOff, int dataLen, 
        byte[] buf, int bufOff, List<Attribute> attributes) throws IOException
	{
        // определить размер блока
        int blockSize = blockSize(); init(); if (dataLen > 0)
        {
            // определить число блоков данных кроме последнего
            int cb = (dataLen - 1) / blockSize * blockSize; 

            // преобразовать данные
            int total = update(data, dataOff, cb, buf, bufOff); 

            // преобразовать данные
            return total + finish(data, dataOff + cb, 
                dataLen - cb, buf, bufOff + total, attributes);
        }
        // преобразовать данные
        else return finish(data, dataOff, dataLen, buf, bufOff, attributes); 
	}
	// преобразовать данные
	@Override public final byte[] transformData(
        byte[] data, int dataOff, int dataLen) throws IOException
    {
        // создать пустой список атрибутов
        List<Attribute> attributes = new ArrayList<Attribute>(); 
        
        // преобразовать данные
        return transformData(data, dataOff, dataLen, attributes); 
    }
	// преобразовать данные
	public byte[] transformData(byte[] data, int dataOff, 
        int dataLen, List<Attribute> attributes) throws IOException
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
            total += finish(data, dataOff + cb, dataLen - cb, buffer, total, attributes); 

            // переразместить буфер
            return (total < buffer.length) ? Arrays.copyOf(buffer, total) : buffer; 
        }
        else {
            // выделить буфер для результата
            byte[] buffer = new byte[blockSize]; 
            
            // преобразовать данные
            int total = finish(data, dataOff, dataLen, buffer, 0, attributes); 

            // переразместить буфер
            return (total < buffer.length) ? Arrays.copyOf(buffer, total) : buffer; 
        }
	}
    // инициализировать алгоритм
    @Override public void init() throws IOException 
    {
        // инициализировать алгоритмы
        hashAlgorithm.init(); transform.init(); 
    } 
	// преобразовать данные
	@Override public int update(byte[] data, int dataOff, 
        int dataLen, byte[] buf, int bufOff) throws IOException
    {
        // захэшировать данные
        if (encrypt) { hashAlgorithm.update(data, dataOff, dataLen);
        
            // зашифровать данные
            return transform.update(data, dataOff, dataLen, buf, bufOff); 
        }
        // расшифровать данные
        else { int cb = transform.update(data, dataOff, dataLen, buf, bufOff); 
        
            // захэшировать данные
            hashAlgorithm.update(buf, bufOff, cb); return cb; 
        }
    }
	// завершить преобразование
	public int finish(byte[] data, int dataOff, int dataLen, byte[] buf, 
        int bufOff, byte[] check, int checkOff) throws IOException
    {
        // проверить корректность размера буфера
        if (check.length < checkOff + checkSize()) throw new IOException(); 
        
        // захэшировать данные
        if (encrypt) { hashAlgorithm.update(data, dataOff, dataLen);
        
            // вычислить контрольную сумму
            hashAlgorithm.finish(check, checkOff); 
            
            // зашифровать данные
            return transform.finish(data, dataOff, dataLen, buf, bufOff); 
        }
        // расшифровать данные
        else { int cb = transform.finish(data, dataOff, dataLen, buf, bufOff); 
            
            // захэшировать данные
            hashAlgorithm.update(buf, bufOff, cb); 
            
            // вычислить контрольную сумму
            byte[] sum = new byte[checkSize()]; hashAlgorithm.finish(sum, 0); 
        
            // сравнить контрольную сумму
            if (!Array.equals(sum, 0, check, checkOff, sum.length)) throw new IOException(); 
            
            return cb; 
        }
    }
	// завершить преобразование
	public int finish(byte[] data, int dataOff, int dataLen, byte[] buf, 
        int bufOff, List<Attribute> attributes) throws IOException
    {
        // выделить память для контрольной суммы
        byte[] sum = new byte[checkSize()]; 
            
        // завершить преобразование
        return finish(data, dataOff, dataLen, buf, bufOff, sum, 0); 
    }
}
