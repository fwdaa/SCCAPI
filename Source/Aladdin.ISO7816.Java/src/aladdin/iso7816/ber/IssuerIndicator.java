package aladdin.iso7816.ber;
import aladdin.iso7816.*; 

///////////////////////////////////////////////////////////////////////////
// Идентификационный номер эмитента (0x42)
///////////////////////////////////////////////////////////////////////////
public class IssuerIndicator extends DataObject
{
    // код издателя и дополнительные данные
    public final byte[] issuer; public final byte[] data;

    // конструктор раскодирования
    public IssuerIndicator(byte[] content) 
    {
        // вызвать базовую функцию
        super(Authority.ISO7816, Tag.ISSUER_INDICATOR, content); 
        
        // указать начальные условия
        int lengthIssuer = 0; int lengthData = content.length * 2;

        // для всех байтов значения
        for (int i = 0; i < content.length && i < 6; i++)
        {
            // проверить корректность данных
            if (((content[i] >>> 4) & 0x0F) <= 9) { lengthIssuer++; lengthData--; } else break; 

            // проверить завершение данных
            if ((content[i] & 0x0F) == 0x0F) { lengthData--; break; }

            // проверить завершение данных
            if ((content[i] & 0x0F) <= 9) { lengthIssuer++; lengthData--; } else break; 
        }
        // выделить память для переменных
        issuer = new byte[lengthIssuer]; data = new byte[lengthData];

        // для всех байтов значения
        for (int i = 0, j = 0; i < content.length; i++)
        {
            // сохранить значение тетрады
            if (lengthIssuer > 2 * i) issuer[2 * i] = (byte)((content[i] >>> 4) & 0x0F); 

            // сохранить значение тетрады
            else data[j++] = (byte)((content[i] >>> 4) & 0x0F); 

            // сохранить значение тетрады
            if (lengthIssuer > 2 * i + 1) issuer[2 * i + 1] = (byte)(content[i] & 0x0F); 

            // проверить наличие незначимых байтов
            else if (lengthIssuer == 2 * i + 1 && ((content[i] & 0x0F) == 0x0F)) {}
                 
            // сохранить значение тетрады
            else data[j++] = (byte)(content[i] & 0xF); 
        }
    }
}
