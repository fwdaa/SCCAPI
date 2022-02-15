package aladdin.capi.mac;
import aladdin.*; 
import aladdin.capi.*; 
import java.security.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм вычисления имитовставки OMAC1
///////////////////////////////////////////////////////////////////////////////
public class OMAC1 extends CBCMAC1
{
    // блочный алгоритм шифрования 
    private final Cipher engine; private final byte[] xor; private byte[] xorK1; 

    // фиксированные константы
    private static final byte[] XOR64 = new byte[] {
        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x1B,
    }; 
    private static final byte[] XOR128 = new byte[] {
        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x87,
    }; 
    // создать алгоритм
    public static OMAC1 create(IBlockCipher blockCipher, byte[] iv) throws IOException
    {
        // указать размер имитовставки по умолчанию
        return create(blockCipher, iv, blockCipher.blockSize() / 2); 
    }
    // создать алгоритм
    public static OMAC1 create(IBlockCipher blockCipher, byte[] iv, int macSize) throws IOException
    {
        // проверить корректность параметров
        if (macSize > blockCipher.blockSize()) throw new IllegalArgumentException();

        // создать режим ECB
        try (Cipher engine = blockCipher.createBlockMode(new CipherMode.ECB()))
        {
            // создать режим CBC
            try (Cipher modeCBC = blockCipher.createBlockMode(new CipherMode.CBC(iv)))
            {
                // создать алгоритм вычисления имитовставки OMAC1
                return new OMAC1(modeCBC, engine, macSize); 
            }
        }
        }
    // конструктор
    public OMAC1(Cipher modeCBC, Cipher engine, int macSize) 
    {
        // вызвать базовую функцию
        super(modeCBC, PaddingMode.NONE, macSize); 
        
        switch (modeCBC.blockSize())
        {
        // указать значение дополнения
        case 8: xor = XOR64; break; case 16: xor = XOR128; break;

        // при ошибке выбросить исключение
        default: throw new IllegalArgumentException(); 
        }
        // сохранить переданные параметры
        this.engine = RefObject.addRef(engine); 
    }  
    // конструктор
	protected OMAC1(Cipher modeCBC, int macSize) { this(modeCBC, null, macSize); }

    // освободить выделенные ресурсы
    @Override protected void onClose() throws IOException
    {
        // освободить выделенные ресурсы
        RefObject.release(engine); super.onClose();
    }
	// инициализировать алгоритм
	@Override public void init(ISecretKey key) throws IOException, InvalidKeyException
    {
        // создать дополнительный ключ
        super.init(key); xorK1 = createXorK1(key); 
    }
	// завершить преобразование
	@Override protected void finish(byte[] data, 
        int dataOff, int dataLen, byte[] mac, int macOff) throws IOException
    {
        // выделить память для полного блока 
        byte[] buffer = new byte[blockSize()]; 
        
        // скопировать последний блок
        System.arraycopy(data, 0, buffer, 0, dataLen); 
        
        // создать дополнительный ключ
        byte[] K = getXorK1(); if (dataLen < buffer.length)
        { 
            // выполнить инверсию бита
            K = createXorK2(K); buffer[dataLen] ^= 0x80;
        }
        // добавить дополнительный ключ
        for (int i = 0; i < buffer.length; i++) buffer[i] ^= K[i]; 
            
        // обработать блок
        super.finish(buffer, 0, buffer.length, mac, macOff); 
    }
    // получить дополнительный ключ
    protected byte[] getXorK1() { return xorK1; }

    // создать дополнительный ключ
    protected byte[] createXorK1(ISecretKey key) throws IOException, InvalidKeyException
    {
        // проверить корректность параметров
        if (engine == null) throw new IllegalStateException(); 

        // создать нулевой блок
        byte[] K1 = new byte[blockSize()]; 
        
        // зашифровать нулевой блок
        engine.encrypt(key, PaddingMode.NONE, K1, 0, K1.length, K1, 0); 
        
        // создать дополнительный ключ
        return createXorK2(K1); 
    }
    // создать дополнительный ключ
    private byte[] createXorK2(byte[] K1)
    {
        // создать нулевой блок
        byte[] K2 = K1.clone(); boolean pad = ((K1[0] & 0x80) != 0);
                
        // для всех байтов блока
        for (int i = 0; i < K1.length; i++)
        {
            // определить операнд с младшими битами
            byte right = (i < K1.length - 1) ? K1[i + 1] : 0; 
                
            // выполнить сдвиг влево
            K2[i] = (byte)((K1[i] << 1) | ((right & 0xFF) >>> 7)); 
                
            // выполнить сложение
            if (pad) K2[i] ^= xor[i];
        }
        return K2; 
    }
}
