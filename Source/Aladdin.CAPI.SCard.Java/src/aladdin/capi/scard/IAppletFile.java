package aladdin.capi.scard;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Файл апплета
///////////////////////////////////////////////////////////////////////////
public interface IAppletFile extends IAppletFileObject
{
    // прочитать данные выбранного файла
    void read(byte[] buffer, int offset) throws IOException;  

    // записать данные в выбранный файл
    void write(byte[] buffer, int offset) throws IOException;
}
