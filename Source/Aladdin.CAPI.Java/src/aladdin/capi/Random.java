package aladdin.capi;
import aladdin.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Генератор случайных данных
///////////////////////////////////////////////////////////////////////////
public class Random extends java.util.Random implements Closeable
{
    // номер версии для сериализации
    private static final long serialVersionUID = -6501944694595773711L;

    // конструктор
    public Random(IRand rand) 
    
        // сохранить переданные параметры
        { this.rand = RefObject.addRef(rand); } private final IRand rand;
     
    // деструктор
    @Override public void close() throws IOException { RefObject.release(rand); }

    // сгенерировать случайные данные
    @Override public void nextBytes(byte[] bytes) 
    {
        // сгенерировать случайные данные
        try { rand.generate(bytes, 0, bytes.length); } 
        
        // обработать возможное исключение
        catch (IOException e) { throw new RuntimeException(e); }
    }
    // сгенерировать число
    @Override public int nextInt() 
    {
        // сгенерировать представление числа
        byte[] encoded = new byte[4]; nextBytes(encoded);

        // вернуть сгенерированное число
        return new java.math.BigInteger(encoded).intValue(); 
    }
    @Override public int nextInt(int i) { return nextInt(); } 
    @Override protected int next(int i) 
    { 
        // сгенерировать число
        int value = nextInt(); if (i == 32) return value; 
        
        // извлечь требуемое число битов
        return value & ((1 << i) - 1); 
    } 
    @Override public long nextLong() 
    {
        // сгенерировать представление числа
        byte[] encoded = new byte[8]; nextBytes(encoded);

        // вернуть сгенерированное число
        return new java.math.BigInteger(encoded).longValue(); 
    }
    @Override public boolean nextBoolean() 
    {
        // сгенерировать байт
        byte[] encoded = new byte[1]; nextBytes(encoded);

        // вернуть булево значение
        return (encoded[0] & 0x01) != 0; 
    }
}
