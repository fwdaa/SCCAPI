package aladdin.capi.gost.rnd;
import aladdin.*; 
import aladdin.capi.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Псевдослучайный генератор случайных данных TK26. 
///////////////////////////////////////////////////////////////////////////
public final class TC026_GOSTR3411_2012_512 extends RefObject implements IRand, Serializable
{
    private static final long serialVersionUID = 1224358444372011800L;
    
    // генератор случайных данных
    private TC026 rand; private byte[] seed; 

    // конструктор
    public TC026_GOSTR3411_2012_512(IRand rand) throws IOException
    {
        // указать алгоритм хэширования
        try (Hash hashAlgorithm = new aladdin.capi.gost.hash.GOSTR3411_2012(512))
        { 
            // выделить память для стартового значения
            seed = new byte[hashAlgorithm.blockSize() - 16]; 

            // сгенерировать стартовое значение
            rand.generate(seed, 0, seed.length); 

            // создать генератор случайных данных
            this.rand = new TC026(null, hashAlgorithm, seed);
        }
    }
    // конструктор
    public TC026_GOSTR3411_2012_512(Object window, byte[] seed) throws IOException
    {
        // указать алгоритм хэширования
        try (Hash hashAlgorithm = new aladdin.capi.gost.hash.GOSTR3411_2012(512))
        { 
            // создать генератор случайных данных
            rand = new TC026(window, hashAlgorithm, seed); this.seed = seed; 
        }
    }
    private void writeObject(ObjectOutputStream oos) throws IOException 
    {
        // записать стартовое значение
        oos.writeObject(seed); 
    }
    private void readObject(ObjectInputStream ois) throws IOException 
    {
        // прочитать стартовое значение
        try { seed = (byte[]) ois.readObject(); }
        
        // обработать возможное исключение
        catch (ClassNotFoundException e) { throw new IOException(e); }
        
        // указать алгоритм хэширования
        try (Hash hashAlgorithm = new aladdin.capi.gost.hash.GOSTR3411_2012(512))
        { 
            // создать генератор случайных данных
            rand = new TC026(null, hashAlgorithm, seed);
        }
    }
    // стартовое значение
    public final byte[] seed() { return seed; }

    // создать генератор случайных данных
    @Override public IRand createRand(Object window) 
    {
        // вернуть генератор случайных данных
        return Rand.rebind(this, window);  
    }
    // сгенерировать случайные данные
	@Override public void generate(byte[] data, int dataOff, int dataLen) throws IOException
    {
	    // сгенерировать случайные данные
        rand.generate(data, dataOff, dataLen); 
    }
    // описатель окна
    @Override public Object window() { return rand.window(); }
}
