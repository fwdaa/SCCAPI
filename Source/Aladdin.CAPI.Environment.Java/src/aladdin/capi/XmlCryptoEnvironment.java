package aladdin.capi;
import aladdin.capi.environment.*;
import java.io.*;
import org.w3c.dom.*;

///////////////////////////////////////////////////////////////////////////
// Криптографическая среда
///////////////////////////////////////////////////////////////////////////
public class XmlCryptoEnvironment extends CryptoEnvironment
{
    // конструктор
	public XmlCryptoEnvironment(String fileName) throws Exception
    {
		// прочитать среду из файла
		super(XmlConfig.readSection(fileName), null);  
    } 
    // конструктор
    public XmlCryptoEnvironment(Document document) throws IOException 
    {
		// прочитать среду из секции конфигурации
		super(XmlConfig.readSection(document), null); 
    }
}
