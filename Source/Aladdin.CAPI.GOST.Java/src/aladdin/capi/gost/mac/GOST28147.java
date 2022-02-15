package aladdin.capi.gost.mac;
import aladdin.*; 
import aladdin.math.*; 
import aladdin.capi.*; 
import aladdin.capi.derive.*;
import java.security.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм вычисления имитовставки ГОСТ 28147
///////////////////////////////////////////////////////////////////////////
public class GOST28147 extends BlockMac
{
    // способ кодирования чисел
    private static final Endian ENDIAN = Endian.LITTLE_ENDIAN; 
    
    private final KeyDerive keyMeshing;    // алгоритм смены ключей
	private final byte[]    sbox;          // таблица подстановок
	private final byte[]    start;         // стартовое значение 
	private final int []    key;           // расписание ключей
	private final byte[]    hash;          // хэш-значение
    
    // текущий ключ и размер данных
    private ISecretKey currentKey; private int length;

    // конструктор
	public GOST28147(byte[] sbox) { this(sbox, new byte[8]); }

    // конструктор
	public GOST28147(byte[] sbox, byte[] start) 
    { 
		// выделить память для расписания ключей
		super(); key = new int[16]; hash = new byte[start.length]; 

		// сохранить параметры алгоритма
		this.sbox = sbox; this.start = start; 
        
        // смена ключа отсутствует
        this.keyMeshing = new NOKDF(ENDIAN); currentKey = null; 
    }
    // конструктор
	public GOST28147(byte[] sbox, byte[] start, KeyDerive keyMeshing) 
	{ 
		// выделить память для расписания ключей
		super(); key = new int[16]; hash = new byte[start.length]; 

		// сохранить параметры алгоритма
		this.sbox = sbox; this.start = start; currentKey = null; 
        
        // указать способ смены ключа
        this.keyMeshing = RefObject.addRef(keyMeshing); 
	}
    // освободить ресурсы
    @Override protected void onClose() throws IOException    
    {
        // освободить ресурсы
        RefObject.release(currentKey);
        
        // освободить ресурсы
        RefObject.release(keyMeshing); super.onClose();
    }
    // тип ключа
    @Override public final SecretKeyFactory keyFactory() 
    { 
        // тип ключа
        return aladdin.capi.gost.keys.GOST28147.INSTANCE; 
    } 
	// размер MAC-значения в байтах
	@Override public final int macSize() { return 4; }
	// размер блока алгоритма хэширования
	@Override public final int blockSize() { return 8; }

	// таблица подстановок
	public final byte[] sbox() { return sbox; }

	///////////////////////////////////////////////////////////////////////
	// Обработка одного блока данных
	///////////////////////////////////////////////////////////////////////
	private void processBlock(byte[] sbox, byte[] src, int srcOff, byte[] dest, int destOff)
	{
		// извлечь обрабатываемый блок
		int N1 = Convert.toInt32(src, srcOff + 0, ENDIAN); 
		int N2 = Convert.toInt32(src, srcOff + 4, ENDIAN); 

		// выполнить 16 шагов
		for (int j = 0; j < 16; j++)
		{
			// выполнить очередной шаг
			int N = N1; N1 = N2 ^ step(sbox, N1, key[j]); N2 = N;
		}
		// вернуть обработанный блок
        Convert.fromInt32(N1, ENDIAN, dest, destOff + 0);
        Convert.fromInt32(N2, ENDIAN, dest, destOff + 4);
	}
	///////////////////////////////////////////////////////////////////////////
	// Тактовая функция
	///////////////////////////////////////////////////////////////////////////
	private static int step(byte[] sbox, int n1, int key)
	{
		// добавить ключ к блоку
		int cm = key + n1; int om = 0;

		// выполнить подстановку
		om = om + ((sbox[      ((cm       ) & 0xF)] & 0xFF)      );
		om = om + ((sbox[ 16 + ((cm >>>  4) & 0xF)] & 0xFF) <<  4);
		om = om + ((sbox[ 32 + ((cm >>>  8) & 0xF)] & 0xFF) <<  8);
		om = om + ((sbox[ 48 + ((cm >>> 12) & 0xF)] & 0xFF) << 12);
		om = om + ((sbox[ 64 + ((cm >>> 16) & 0xF)] & 0xFF) << 16);
		om = om + ((sbox[ 80 + ((cm >>> 20) & 0xF)] & 0xFF) << 20);
		om = om + ((sbox[ 96 + ((cm >>> 24) & 0xF)] & 0xFF) << 24);
		om = om + ((sbox[112 + ((cm >>> 28) & 0xF)] & 0xFF) << 28);

		// выполнить циклический сдвиг
		return om << 11 | om >>> (32 - 11);
	}
	///////////////////////////////////////////////////////////////////////////
    // установить значение ключа
	///////////////////////////////////////////////////////////////////////////
    protected final void resetKey(ISecretKey key) throws InvalidKeyException
    {
		// проверить тип ключа
		byte[] value = key.value(); if (value == null)
		{
			// при ошибке выбросить исключение
			throw new InvalidKeyException();
		}
        // установить ключ
		for (int i = 0; i < 8; i++) 
		{
			this.key[i + 0] = Convert.toInt32(value, i * 4, ENDIAN); 
			this.key[i + 8] = Convert.toInt32(value, i * 4, ENDIAN);
		}
    }
	///////////////////////////////////////////////////////////////////////////
	// Вычисление имитовставки
	///////////////////////////////////////////////////////////////////////////
	@Override public void init(ISecretKey key) throws IOException, InvalidKeyException 
	{ 
        // освободить выделенные ресурсы
        RefObject.release(currentKey); currentKey = null; 
        
		// установить ключ
		super.init(key); resetKey(key); currentKey = RefObject.addRef(key); 
        
		// скопировать стартовое значение
        System.arraycopy(start, 0, hash, 0, hash.length); length = 0; 
	}
	@Override protected void update(byte[] data, int dataOff) throws IOException
	{
		// наложить открытый текст на текущее хэш-значение
		for (int j = 0; j < blockSize(); j++) hash[j] ^= data[dataOff + j];

		// зашифровать текущее хэш-значение
		processBlock(sbox, hash, 0, hash, 0); 
        
        // увеличить размер данных
        length += blockSize(); if ((length % 1024) != 0) return; 

        // изменить значение ключа
        try (ISecretKey newKey = keyMeshing.deriveKey(currentKey, null, keyFactory(), 32))
        {
            // переустановить ключ
            if (newKey != currentKey) resetKey(newKey); 

            // сохранить новый текущий ключ
            RefObject.release(currentKey); currentKey = RefObject.addRef(newKey); 
        }
        // обработать неожидаемое исключение
        catch (InvalidKeyException e) { throw new RuntimeException(e); }
	}
	@Override protected void finish(byte[] data, 
        int dataOff, int dataLen, byte[] buf, int bufOff) throws IOException
	{
        // проверить наличие данных
        if ((length + dataLen) == 0) 
        { 
            // вернуть стартовое хэш-значение
            System.arraycopy(hash, 0, buf, bufOff, macSize()); return; 
        } 
		// выделить память для блока
		byte[] buffer = new byte[blockSize()];

		// скопировать данные
		System.arraycopy(data, dataOff, buffer, 0, dataLen);

		// дополнить неполный блок нулями
		for (int i = dataLen; i < blockSize(); i++) buffer[i] = 0; 

	    // обработать созданный блок
		update(buffer, 0); if (length == 8)
        {
			// создать нулевой блок
		    for (int i = 0; i < blockSize(); i++) buffer[i] = 0; 
            
		    // обработать созданный блок
            update(buffer, 0); 
        }
		// выделить из хэш-значения имитовставку
		System.arraycopy(hash, 0, buf, bufOff, macSize());
        
        // освободить выделенные ресурсы
        RefObject.release(currentKey); currentKey = null; 
	}
}
