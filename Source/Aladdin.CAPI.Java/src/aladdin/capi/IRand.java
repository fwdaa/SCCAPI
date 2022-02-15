package aladdin.capi;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Генерация случайных данных
///////////////////////////////////////////////////////////////////////////
public interface IRand extends IAlgorithm
{
	// сгенерировать случайные данные
	void generate(byte[] data, int dataOff, int dataLen) throws IOException;
    
    // объект окна
    Object window(); 
}
