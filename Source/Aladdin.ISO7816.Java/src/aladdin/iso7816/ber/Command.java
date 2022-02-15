package aladdin.iso7816.ber;
import aladdin.iso7816.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Команда на выполнение (0x52)
///////////////////////////////////////////////////////////////////////////
public class Command extends DataObject
{
    // команда APDU
    public final aladdin.iso7816.Command value; 

    // конструктор закодирования
    public Command(aladdin.iso7816.Command value) 
    {
        // сохранить переданные параметры
        super(Authority.ISO7816, Tag.COMMAND_APDU, value.encoded());  

        // сохранить переданные параметры
        this.value = value; 
    }
    // конструктор раскодирования
    public Command(byte[] content) throws IOException
    {
        // сохранить переданные параметры
        super(Authority.ISO7816, Tag.COMMAND_APDU, content);  

        // раскодировать команду
        value = new aladdin.iso7816.Command(content); 
    }
}
