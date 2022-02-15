package aladdin.iso7816.ber;
import aladdin.iso7816.*; 
import aladdin.iso7816.Command; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Исходные данные доступа (0x44)
///////////////////////////////////////////////////////////////////////////
public class InitialAccessData extends DataObject
{
    // конструктор
    public InitialAccessData(byte[] content) throws IOException 
    {
        // сохранить переданные параметры
        super(Authority.ISO7816, Tag.INITIAL_ACCESS_DATA, content); 
        
        // вернуть значение команды
        if (content.length >= 5) { command = new Command(content); } 

        // в зависимости от размера
        else if (content.length == 1)
        {
            // указать команду READ BINARY
            command = new Command((byte)0x00, INS.READ_BINARY, (byte)0x00, (byte)0x00, content, 0); 
        }
        // в зависимости от размера
        else if (content.length == 2 && (content[0] & 0x80) != 0)
        {
            // указать команду READ BINARY
            command = new Command((byte)0x00, INS.READ_BINARY, content[0], (byte)0x00, new byte[] { content[1] }, 0); 
        }
        // в зависимости от размера
        else if (content.length == 2 && (content[0] & 0x80) == 0)
        {
            // вычилить значение параметра P2
            byte P2 = (byte)(((content[0] & 0x1F) << 3) | 0x6); 

            // указать команду READ RECORD(S)
            command = new Command((byte)0x00, INS.READ_RECORDS, (byte)0x01, P2, new byte[] { content[1] }, 0); 
        }
        // при ошибке выбросить исключение
        else throw new IOException(); 
    }
    // значение объекта
    public final Command command; 
}
