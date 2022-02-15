package aladdin.iso7816;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Команда APDU
///////////////////////////////////////////////////////////////////////////
public class Command
{
    // класс и код команды 
    public final byte CLA; public final byte INS; 
    // параметры команды
    public final byte P1; public final byte P2; 

    // данные команды и ожидаемый размер ответа
    public final byte[] data; public final int Ne; 

    // конструктор
    public Command(byte cla, byte ins, byte p1, byte p2)
    {
        // сохранить переданные параметры
        this(cla, ins, p1, p2, new byte[0], 0); 
    }
    // конструктор
    public Command(byte cla, byte ins, byte p1, byte p2, byte[] data)
    {
        // сохранить переданные параметры
        this(cla, ins, p1, p2, data, 0); 
    }
    // конструктор
    public Command(byte cla, byte ins, byte p1, byte p2, byte[] data, int ne) 
    {
        // проверить наличие данных
        if (data == null) data = new byte[0]; this.data = data; 

        // проверить корректность данных
        if (data.length > 0xFFFF || ne > 0x10000) throw new IllegalArgumentException(); 

        // сохранить переданные параметры
        CLA = cla; INS = ins; P1 = p1; P2 = p2; Ne = ne; 

        // в зависимости от размеров
        if (data.length <= 255 && ne <= 256)
        {
            // проверить наличие данных в запросе или ответе
            if (data.length == 0 && ne == 0) encoded = new byte[4 + data.length];

            // при наличии данных в запросе
            else if (data.length != 0 && ne == 0) 
            { 
                // указать размер данных в запросе
                encoded = new byte[5 + data.length]; encoded[4] = (byte)data.length; 

                // скопировать данные
                System.arraycopy(data, 0, encoded, 5, data.length); 
            }
            // при наличии данных в ответе
            else if (data.length == 0 && ne != 0) 
            { 
                // выделить память для представления
                encoded = new byte[5 + data.length]; 

                // указать максимальный размер данных в ответе
                encoded[encoded.length - 1] = (byte)(ne % 256); 
            }
            // выделить память для представления
            else { encoded = new byte[6 + data.length]; 

                // указать размер данных в запросе
                encoded[4] = (byte)data.length; 

                // скопировать данные
                System.arraycopy(data, 0, encoded, 5, data.length); 

                // указать максимальный размер данных в ответе
                encoded[encoded.length - 1] = (byte)(ne % 256); 
            }
        }
        else { 
            // при наличии данных в запросе
            if (data.length != 0 && ne == 0) 
            { 
                // выделить память для представления
                encoded = new byte[7 + data.length]; encoded[4] = 0x00; 

                // указать размер данных в запросе
                encoded[5] = (byte)(data.length >>> 8); encoded[6] = (byte)(data.length & 0xFF); 

                // скопировать данные
                System.arraycopy(data, 0, encoded, 7, data.length); 
            }
            // при наличии данных в ответе
            else if (data.length == 0 && ne != 0) 
            { 
                // выделить память для представления
                encoded = new byte[7 + data.length]; encoded[4] = 0x00; 

                // указать максимальный размер данных в ответе
                encoded[encoded.length - 2] = (byte)(ne >>>  8); 
                encoded[encoded.length - 1] = (byte)(ne & 0xFF); 
            }
            else { 
                // выделить память для представления
                encoded = new byte[9 + data.length]; encoded[4] = 0x00; 

                // указать размер данных в запросе
                encoded[5] = (byte)(data.length >>> 8); encoded[6] = (byte)(data.length & 0xFF); 

                // скопировать данные
                System.arraycopy(data, 0, encoded, 7, data.length); 

                // указать максимальный размер данных в ответе
                encoded[encoded.length - 2] = (byte)(ne >>>  8); 
                encoded[encoded.length - 1] = (byte)(ne & 0xFF); 
            }
        }
        // установить заголовок команды
        encoded[0] = cla; encoded[1] = ins; encoded[2] = (byte)(p1 & 0xFF); encoded[3] = (byte)(p2 & 0xFF); 
    }
    // раскодировать команду
    public Command(byte[] encoded) throws IOException
    {
        // проверить размер команды
        if (encoded.length < 4) throw new IOException(); this.encoded = encoded; 

        // извлечь заголовок команды
        CLA = encoded[0]; INS = encoded[1]; P1 = encoded[2]; P2 = encoded[3];

        // проверить наличие данных или размера
        if (encoded.length == 4) { data = new byte[0]; Ne = 0; return; }
        if (encoded.length == 5) { data = new byte[0]; 
                
            // извлечь максимальный размер данных в ответе
            Ne = (encoded[4] == 0) ? 256 : encoded[4]; return; 
        }
        // для короткого формата
        if (encoded[4] != 0x00) {

            // при отсутствии размера ответа
            if (5 + encoded[4] == encoded.length) { Ne = 0; 
                
                // скопировать данные
                data = new byte[encoded[4]]; System.arraycopy(encoded, 5, data, 0, data.length); 
            }
            // при наличии размера ответа
            else if (6 + encoded[4] == encoded.length) 
            { 
                // скопировать данные
                data = new byte[encoded[4]]; System.arraycopy(encoded, 5, data, 0, data.length); 

                // извлечь максимальный размер данных в ответе
                Ne = (encoded[encoded.length - 1] == 0) ? 256 : encoded[encoded.length - 1];
            }
            // при ошибке выбросить исключение
            else throw new IOException(); 
        }
        else { 
            // проверить корректность данных
            if (encoded.length == 6) throw new IOException();

            // при отсутствии данных
            if (encoded.length == 7) { data = new byte[0];
                
                // извлечь максимальный размер данных в ответе
                if ((encoded[encoded.length - 2] == 0 && encoded[encoded.length - 1] == 0)) Ne = 0x10000;
                
                // извлечь максимальный размер данных в ответе
                else { Ne = (encoded[encoded.length - 2] << 8) | encoded[encoded.length - 1]; }
            }
            else { 
                // извлечь размер данных в запросе
                int length = (encoded[5] << 8) | encoded[6]; 

                // при отсутствии размера ответа
                if (7 + length == encoded.length) { Ne = 0;
                    
                    // скопировать данные
                    data = new byte[length]; System.arraycopy(encoded, 7, data, 0, data.length);
                }
                // при наличии размера ответа
                else if (9 + length == encoded.length)
                { 
                    // извлечь максимальный размер данных в ответе
                    if ((encoded[encoded.length - 2] == 0 && encoded[encoded.length - 1] == 0)) Ne = 0x10000;
                
                    // извлечь максимальный размер данных в ответе
                    else { Ne = (encoded[encoded.length - 2] << 8) | encoded[encoded.length - 1]; }
                    
                    // скопировать данные
                    data = new byte[length]; System.arraycopy(encoded, 7, data, 0, data.length); 
                }
                // при ошибке выбросить исключение
                else throw new IOException(); 
            }
        }
    }
    // закодированное представление
    public byte[] encoded() { return encoded; } private final byte[] encoded; 

    // признак наличия длинных размеров
    public boolean isLong() { return encoded.length >= 7 && encoded[4] == 0x00; } 
}
