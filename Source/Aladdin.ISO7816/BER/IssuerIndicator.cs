namespace Aladdin.ISO7816.BER
{
    ///////////////////////////////////////////////////////////////////////////
    // Идентификационный номер эмитента (0x42)
    ///////////////////////////////////////////////////////////////////////////
    public class IssuerIndicator : DataObject
    {
        // код издателя и дополнительные данные
        public readonly byte[] Issuer; public readonly byte[] Data;

        // конструктор раскодирования
        public IssuerIndicator(byte[] content) : base(Authority.ISO7816, ISO7816.Tag.IssuerIndicator, content)
        {
            // указать начальные условия
            int lengthIssuer = 0; int lengthData = content.Length * 2;

            // для всех байтов значения
            for (int i = 0; i < content.Length && i < 6; i++)
            {
                // проверить корректность данных
                if ((content[i] >> 4) <= 9) { lengthIssuer++; lengthData--; } else break; 

                // проверить завершение данных
                if ((content[i] & 0xF) == 0xF) { lengthData--; break; }

                // проверить завершение данных
                if ((content[i] & 15) <= 9) { lengthIssuer++; lengthData--; } else break; 
            }
            // выделить память для переменных
            Issuer = new byte[lengthIssuer]; Data = new byte[lengthData];

            // для всех байтов значения
            for (int i = 0, j = 0; i < content.Length; i++)
            {
                // сохранить значение тетрады
                if (lengthIssuer > 2 * i) Issuer[2 * i] = (byte)(content[i] >> 4); 

                // сохранить значение тетрады
                else Data[j++] = (byte)(content[i] >> 4); 

                // сохранить значение тетрады
                if (lengthIssuer > 2 * i + 1) Issuer[2 * i + 1] = (byte)(content[i] & 0xF); 

                // проверить наличие незначимых байтов
                else if (lengthIssuer == 2 * i + 1 && ((content[i] & 0xF) == 0xF)) {}
                 
                // сохранить значение тетрады
                else Data[j++] = (byte)(content[i] & 0xF); 
            }
        }
    }
}
