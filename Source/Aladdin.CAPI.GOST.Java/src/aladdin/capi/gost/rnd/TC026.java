package aladdin.capi.gost.rnd;
import aladdin.*; 
import aladdin.capi.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Псевдослучайный генератор случайных данных TK26. 
// Генерация производится в сторону байтов с младшими адресами. 
///////////////////////////////////////////////////////////////////////////
public class TC026 extends RefObject implements IRand
{
    // функция проверки качества 
    public static abstract class CheckQuality    
    {
        // проверить качество последовательности
        public abstract boolean invoke(byte[] data); 
    }; 
    // алгоритм хэширования и текущее состояние
    private final Hash algorithm; private final byte[] U; 
        
    // текущее хэш-значение и номер текущего байта
    private final byte[] C; private int offset; private CheckQuality check; 

    // конструктор
    public TC026(Object window, Hash algorithm, byte[] seed, CheckQuality check)
    {
        // определить размер блока функции хэширования
        int blockSize = algorithm.blockSize(); if (blockSize < 64) 
        {
            // при ошибке выбросить исключение
            throw new IllegalArgumentException();
        }
        // проверить корректность параметров
        if (seed.length < 32 || seed.length > blockSize - 16) 
        {
            // при ошибке выбросить исключение
            throw new IllegalArgumentException();
        }
        // сохранить переданные параметры
        this.window = window; this.check = check; 
        
        // сохранить алгоритм хэширования 
        this.algorithm = RefObject.addRef(algorithm); 

        // выделить буферы требуемого размера
        U = new byte[blockSize - 1]; C = new byte[algorithm.hashSize()]; 
            
        // скопировать начальное значение
        System.arraycopy(seed, 0, U, 0, seed.length); offset = 0; 

        // выполнить дополнение нулями
        for (int i = seed.length; i < U.length; i++) U[i] = 0; 
    }
    // освободить ресурсы
    @Override protected void onClose() throws IOException    
    { 
        // освободить ресурсы
        RefObject.release(algorithm); super.onClose();
    }
    // создать генератор случайных данных
    @Override public IRand createRand(Object window) 
    {
        // вернуть генератор случайных данных
        return Rand.rebind(this, window);  
    }
    // сгенерировать случайные данные
	@Override public void generate(byte[] data, int dataOff, int dataLen) throws IOException
    {
        // проверить необходимость действий
        if (dataLen == 0) return; if (offset > 0)
        {
            // определить число копируемых байтов
            int length = (offset > dataLen) ? dataLen : offset; 

            // скопировать случайные данные
            System.arraycopy(C, offset - length, data, dataOff + dataLen - length, length); 

            // вычислить размер оставшихся данных
            offset -= length; dataLen -= length; 
        }
        // для всех целых блоков
        for (; dataLen >= C.length; dataLen -= C.length)
        {
            // сгенерировать новый блок
            generateNext(); 

            // скопировать хэш-значение в выходные данные
            System.arraycopy(C, 0, data, dataOff + dataLen - C.length, C.length); 
        }
        // для неполного блока
        if (dataLen > 0)
        {
            // сгенерировать новый блок
            generateNext(); offset = C.length - dataLen; 
                
            // скопировать случайные данные
            System.arraycopy(C, offset, data, dataOff, dataLen); 
        }
    }
    private void generateNext() throws IOException
    {
        do {
            // выполнить инкремент состояния
            for (int i = U.length - 1; i >= 0; i--) { if (++U[i] != 0) break; }

            // захэшировать состояние
            algorithm.init(); algorithm.update(U, 0, U.length); 

            // вычислить хэш-значение
            algorithm.finish(C, 0);
        }
        // проверить качество последовательности
        while (check != null && !check.invoke(C)); 
    }
    // описатель окна
    @Override public Object window() { return window; } private final Object window; 
}
