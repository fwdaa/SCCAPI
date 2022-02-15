package aladdin.pcsc;
import aladdin.util.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Криптографическая смарт-карта
///////////////////////////////////////////////////////////////////////////
public final class Card implements ICard
{
    // модуль и область видимости
    private final Module module; private final ReaderScope scope; 
    // считыватель смарт-карты и ATR
    private final Reader reader; private final byte[] atr; 

    // производитель и модель смарт-карты
    private String manufacturer; private String model; 
    // номер версии и серийный номер
    private String version; private byte[] serial; 
    
    // конструктор
    public Card(Module module, ReaderScope scope, Reader reader) throws IOException
    {
        // сохранить переданные параметры
        this.module = module; this.scope = scope; this.reader = reader;
        
        // указать режим открытия сеанса
        OpenMode openMode = OpenMode.SHARED; int protocols = Protocol.T0 | Protocol.T1; 
        
        // создать сеанс со считывателем
        try (ReaderSession session = reader.createSession(openMode, protocols))
        {
            // получить ATR смарт-карты
            atr = session.atr().encoded; manufacturer = null;
            try { 
                // получить имя производителя
                byte[] encoded = session.getAttribute(API.SCARD_ATTR_VENDOR_NAME);
               
                // раскодировать имя производителя
                try { manufacturer = new String(encoded, "UTF-8"); } catch (Throwable e) 
                {
                    // указать шестнадцатеричное представление
                    manufacturer = Array.toHexString(encoded); 
                }
            }
            catch (Throwable e) {} model = null; try 
            {
                // получить название модели
                byte[] encoded = session.getAttribute(API.SCARD_ATTR_VENDOR_IFD_TYPE);

                // раскодировать название модели
                try { model = new String(encoded, "UTF-8"); } catch (Throwable e) 
                {
                    // указать шестнадцатеричное представление
                    model = Array.toHexString(encoded); 
                }
            }
            catch (Throwable e) {} version = null; try 
            {  
                // получить номер версии
                byte[] encoded = session.getAttribute(API.SCARD_ATTR_VENDOR_IFD_VERSION);

                // проверить корректность размера 
                if (encoded.length != 4) version = null; 

                // сохранить номер версии
                version = String.format("%1$d.%2$d.%3$d", 
                    encoded[3], encoded[2], (encoded[1] << 8) | encoded[0]
                ); 
            }
            // обработать возможную ошибку
            catch (Throwable e) {} serial = null; try 
            { 
                // получить серийный номер смарт-карты
                serial = session.getAttribute(API.SCARD_ATTR_VENDOR_IFD_SERIAL_NO); 
            }
            // обработать возможную ошибку
            catch (Throwable e) {}
        }
    }
    // считыватель 
    @Override public Reader reader() { return reader; } 

    // атрибуты смарт-карты
    public String manufacturer() { return manufacturer; }
    public String model       () { return model;        }
    public String version     () { return version;      }
    public byte[] serial      () { return serial;       }
    public byte[] atr         () { return atr;          } 
        
    // состояние смарт-карты
    @Override public CardState getState() throws IOException 
    { 
	    // создать используемый контекст
	    long hContext = module.establishContext(scope); 
        try {
            // получить информацию о состоянии
            return module.getCardState(hContext, reader.name()); 
        }
        // освободить выделенные ресурсы
        finally { module.releaseContext(hContext); } 
    }
    // серийный номер смарт-карты
    public byte[] getSerialNumber() throws IOException
    {
        // указать режим открытия сеанса
        OpenMode openMode = OpenMode.SHARED; int protocols = Protocol.T0 | Protocol.T1; 

        // создать сеанс работы со смарт-картой
        try (ReaderSession session = reader.createSession(openMode, protocols))
        {
            // получить серийный номер смарт-карты
            return session.getAttribute(API.SCARD_ATTR_VENDOR_IFD_SERIAL_NO); 
        }
        // обработать отсуствие атрибута
        catch (Throwable e) { return null; }
    }
}
