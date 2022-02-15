package aladdin.capi;
import aladdin.*; 
import java.io.*; 
import java.util.*;

///////////////////////////////////////////////////////////////////////////////
// Поток ввода / вывода в память
///////////////////////////////////////////////////////////////////////////////
public final class MemoryStream
{
    // буфер, позиция начала данных и используемый размер
    private byte[] buffer; private int origin; private int capacity; 
    
    // размер данных в буфере и текущая позиция 
    private int length; private int position; 
    
    // признак расширяемости и допустимости записи
    private final boolean expandable; private final boolean writable; 
    
    // конструктор
    public MemoryStream() { this(0); }
    
    // конструктор
    public MemoryStream(int capacity) 
    {
        // проверить корректность данных
        if (capacity < 0) throw new IllegalArgumentException(); 
        
        // выделить буфер требуемого размера
        buffer = new byte[capacity]; this.capacity = capacity; 
        
        // указать атрибуты буфера
        origin = length = position = 0; expandable = writable = true; 
    }
    // конструктор
    public MemoryStream(byte[] buffer) { this(buffer, true); }
    
    // конструктор
    public MemoryStream(byte[] buffer, boolean writable) 
    {
        // проверить корректность данных
        if (buffer == null) throw new IllegalArgumentException(); 
        
        // сохранить переданный буфер
        this.buffer = buffer; capacity = length = buffer.length; 
        
        // указать атрибуты буфера
        origin = position = 0; expandable = false; this.writable = writable;
    }
    // конструктор
    public MemoryStream(byte[] buffer, int index, int count) 
    {
        // сохранить переданные параметры
        this(buffer, index, count, true); 
    }
    // конструктор
    public MemoryStream(byte[] buffer, int index, int count, boolean writable)
    {
        // проверить корректность данных
        if (buffer == null) throw new IllegalArgumentException(); 
        
        // проверить корректность данных
        if (index < 0 || count < 0) throw new IllegalArgumentException();
        
        // проверить корректность данных
        if (buffer.length - index < count) throw new IllegalArgumentException();
        
        // сохранить переданный буфер
        this.buffer = buffer; capacity = length = count; origin = index; 
        
        // указать размер буфера
        position = 0; expandable = false; this.writable = writable; 
    }
    // сравнение буферов
    public boolean equals(MemoryStream other)
    {
        // сравнить адреса буферов
        return other != null && buffer == other.buffer; 
    }
    // сравнение буферов
    @Override public boolean equals(Object other)
    {
        // проверить тип объекта
        if (other == null || !(other instanceof MemoryStream)) return false; 
        
        // выполнить сравнение буферов
        return equals((MemoryStream)other); 
    }
    // вычислить хэш-код
    @Override public int hashCode() { return Arrays.hashCode(buffer); }
    
    // получить данные буфера
    public final byte[] toArray() { byte[] copy = new byte[length]; 
        
        // скопировать данные в буфер
        System.arraycopy(buffer, origin, copy, 0, length); return copy; 
    }
    // признак допустимости позиционирования / чтения / записи 
    public final boolean canRead () { return true;     } 
    public final boolean canWrite() { return writable; }  
    
    // получить текущую позицию / размер потока
    public final int position() { return position; }
    public final int length  () { return length;   } 
    
    // получить размер буфера
    public final int capacity() { return capacity; }
    
    // установить размер буфера
    public final void capacity(int capacity) throws IOException
    {
        // проверить корректность данных
        if (capacity < length) throw new IllegalArgumentException();
        
        // проверить необходимость действий
        if (this.capacity == capacity) return; 
        
        // проверить допустимость расширения
        if (!expandable) throw new IOException(); 
        
        // выделить буфер требуемого размера
        byte[] newBuffer = new byte[capacity]; 
        
        // скопировать данные в буфер
        System.arraycopy(buffer, origin, newBuffer, 0, length);
        
        // переустановить указатели
        buffer = newBuffer; origin = 0; this.capacity = capacity; 
    }
    // установить текущую позицию потока
    public final void position(int position)
    {
        // проверить корректность позиции
        if (position < 0) throw new IllegalArgumentException(); 

        // установить новую позицию
        this.position = position; 
    }
    // установить размер потока
    public final void length(int length) throws IOException
    {
        // проверить корректность размера
        if (length < 0) throw new IllegalArgumentException();
        
        // проверить допустимость записи
        if (!canWrite()) throw new IOException(); 
        
        // обеспечить достаточность буфера
        if (length > capacity) capacity(length); 
        
        // при увеличении размера
        if (length > this.length) 
        {
            // обнулить неиспользуемые данные
            Arrays.fill(buffer, origin + this.length, length, (byte)0); 
        }
        // установить новый размер
        this.length = length; 
        
        // скорректировать позицию в буфере
        if (position > this.length) position = this.length; 
    }
    // прочитать данные
    public final int read(byte[] buffer, int offset, int count)
    {
        // проверить корректность данных
        if (buffer == null) throw new IllegalArgumentException(); 
        
        // проверить корректность данных
        if (offset < 0 || count < 0) throw new IllegalArgumentException();
        
        // проверить корректность данных
        if (buffer.length - offset < count) throw new IllegalArgumentException();
        
        // определить число считываемых байт
        if (count > length - position) count = length - position; 
        
        // прочитать требуемое число байтов
        System.arraycopy(this.buffer, origin + position, buffer, offset, count); 
        
        // изменить текущую позицию
        position = position + count; return count; 
    }
    // записать данные
    public final void write(byte[] buffer, int offset, int count) throws IOException
    {
        // проверить корректность данных
        if (buffer == null) throw new IllegalArgumentException(); 
        
        // проверить корректность данных
        if (offset < 0 || count < 0) throw new IllegalArgumentException();
        
        // проверить корректность данных
        if (buffer.length - offset < count) throw new IllegalArgumentException();
        
        // проверить корректность данных
        if ((long)position + count >= 0x100000000L) throw new IllegalArgumentException();
        
        // проверить допустимость записи
        if (!canWrite()) throw new IOException(); 
        
        // обеспечить достаточность буфера
        if (position + count > capacity) capacity(position + count); 
        
        // записать требуемое число байтов
        System.arraycopy(buffer, offset, this.buffer, origin + position, count); 
        
        // изменить текущую позицию и размер данных
        position = position + count; if (position > length) length = position; 
    }
    // синхронизировать данные
    public final void flush() {}
}
