package aladdin.asn1;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Строка флагов
///////////////////////////////////////////////////////////////////////////
public final class BitFlags extends BitString
{
    private final long numeric; // численное значение

    // конструктор при раскодировании
    public BitFlags(IEncodable encodable) throws IOException
    {
    	super(encodable); long number = 0; 

        // определить последний ненулевой байт
		int cb = value.length; while (cb >= 1 && value[cb - 1] == 0) cb--;

		// проверить наличие ненулевых байтов
		if (cb == 0) { value = new byte[0]; bits = 0; numeric = number; return; }

        // выделить память для нового массива
        byte[] resizeValue = new byte[cb]; number = 0;
        
		// скопировать данные
        System.arraycopy(value, 0, resizeValue, 0, cb); value = resizeValue; 
        
        // для всех битов ненулевого байта
		for (int i = 0; i < 8; i++)
		{
            // извлечь бит
            byte bt = (byte)((value[cb - 1] >>> i) & 0x1);

            // установить число битов
            if (bits == 0 && bt != 0) bits = 8 * cb - i;

            // изменить позицию бита
            number = (number << 1) | bt;
		}
		// для всех байтов 
		for (int i = cb - 2; i >= 0; i--)
		{
            // для всех битов
            for (int j = 0; j < 8; j++)
            {
                // извлечь бит
				byte bt = (byte)((value[i] >>> j) & 0x1);

				// изменить позицию бита
				number = number << 1 | bt;
            }
		}
        numeric = number; 
    }
    // конструктор при закодировании
    public BitFlags(long flags)
    {
    	super(new byte[8], 64); numeric = flags;

        // для всех байтов
		for (int i = 0; i < 8; i++)
		{
            // извлечь байт
            byte b = (byte)((flags >>> (8 * i)) & 0xFF);

            // для всех битов
            for (int j = 0; j < 8; j++)
            {
                // извлечь бит
                byte bt = (byte)((b >>> j) & 0x1);

				// изменить позицию бита
                value[i] |= (byte)(bt << (7 - j));
            }
        }
        // определить последний ненулевой байт
        int cb = 8; while (cb >= 1 && value[cb - 1] == 0) cb--;

        // проверить наличие ненулевых байтов
        if (cb == 0) { value = new byte[0]; bits = 0; return; }

        // выделить память для нового массива
        byte[] resizeValue = new byte[cb]; 
        
        // скопировать данные
        System.arraycopy(value, 0, resizeValue, 0, cb); value = resizeValue; 
        
        // для всех битов ненелевого байта
        for (int i = 0; i < 8; i++)
        {
            // найти ненулевой бит
            if ((value[cb - 1] & (1 << i)) == 0) continue;

            // установить число битов
            bits = 8 * cb - i; return;
        }
    }
    // численное представление
    public final long flags() { return numeric; }
}