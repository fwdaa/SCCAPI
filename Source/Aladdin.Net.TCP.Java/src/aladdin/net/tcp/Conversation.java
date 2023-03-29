package aladdin.net.tcp;
import aladdin.*;
import aladdin.net.*;
import java.io.*; 
import java.net.*; 
import java.util.*;

///////////////////////////////////////////////////////////////////////////
// Диалог TCP
///////////////////////////////////////////////////////////////////////////
public class Conversation extends aladdin.net.Conversation
{
    // используемый сокет
    private final Socket socket; private boolean closed; 
    // способ сериализации данных
    private final Serialization serialization; 
    
    // конструктор
	protected Conversation(Socket socket, aladdin.io.Serialization serialization) throws IOException
	{
        // сохранить переданные параметры
        this.socket = socket; socket.setReceiveBufferSize(65536); closed = false; 
        
        // указать способ сериализации данных
        this.serialization = new BinarySerialization<Integer>(serialization); 
    }
	// выполнить освобождение ресурсов
    @Override protected void onClose() throws IOException
    { 
        // выполнить освобождение ресурсов
        if (!closed) socket.close(); closed = true; super.onClose();  
    }
    // признак освобождения ресурсов
    @Override public boolean inactive() { return closed; }
    
    // создать способ записи/чтения данных
    @Override public Serializer getSerializer(Class<?> type)
    {
        // создать способ записи/чтения данных
        return serialization.getSerializer(type); 
    }
    ///////////////////////////////////////////////////////////////////////
	// Локальный и удаленный порты
	///////////////////////////////////////////////////////////////////////
    public int localPort () { return socket.getLocalPort(); }
    public int remotePort() { return socket.getPort     (); }
    
	///////////////////////////////////////////////////////////////////////
    // Управление диалогом
	///////////////////////////////////////////////////////////////////////
    @SuppressWarnings({"unchecked"}) 
    @Override public Exception decodeException(Message message) throws IOException
    {
        // проверить тип сообщения 
        if (message == null || !message.type().equals(-1)) return null; 

        // извлечь содержимое сообщения
        byte[] body = ((BinaryMessage<Integer>)message).body(); 

        // раскодировать исключение
        return SerialException.fromString(new String(body, "UTF-8")); 
    }
    @Override public boolean isEndDialog(Message message) 
    { 
        // признак завершения диалога
        return message.type().equals(0); 
    }
    public void end(Throwable exception) throws IOException
    {
        // проверить указание исключения
        if (exception == null) { end(); return; } 
        
        // проверить закрытие соединения
        if (inactive()) return; int timeout = 0; 
        
	    // закодировать исключение
        String error = SerialException.toString(exception, false); 
        
        // передать сообщение о завершении
        send(-1, error.getBytes("UTF-8"), timeout); 
    }
    public void end() throws IOException
    {
        // проверить закрытие соединения
        if (inactive()) return; int timeout = 0; 
        
        // передать сообщение о завершении
        send(0, new byte[0], timeout); 
    }
	///////////////////////////////////////////////////////////////////////
	// Передать сообщение
	///////////////////////////////////////////////////////////////////////
    @SuppressWarnings({"unchecked"}) 
    @Override public void send(Message message, int timeout) throws IOException
    {
        // выполнить преобразование типа
        BinaryMessage<Integer> binaryMessage = (BinaryMessage<Integer>)message; 
        
        // указать тип и содержимое сообщения 
        int type = binaryMessage.type(); byte[] body = binaryMessage.body(); 
        
        // проверить наличие данных
        if (body == null) body = new byte[0]; 
        
        // выделить память для представления
        byte[] encoded = new byte[8 + body.length]; 
            
        // закодировать общий размер  
        encoded[0] = (byte)((encoded.length       ) & 0xFF); 
        encoded[1] = (byte)((encoded.length >>>  8) & 0xFF); 
        encoded[2] = (byte)((encoded.length >>> 16) & 0xFF); 
        encoded[3] = (byte)((encoded.length >>> 24) & 0xFF); 

        // закодировать тип данных
        encoded[4] = (byte)((type       ) & 0xFF); 
        encoded[5] = (byte)((type >>>  8) & 0xFF); 
        encoded[6] = (byte)((type >>> 16) & 0xFF); 
        encoded[7] = (byte)((type >>> 24) & 0xFF); 
        
        // скопировать тело сообщения
        System.arraycopy(body, 0, encoded, 8, body.length); 
        
        // передать сообщение
        socket.getOutputStream().write(encoded); 
    }
	///////////////////////////////////////////////////////////////////////
    // Получить сообщение
	///////////////////////////////////////////////////////////////////////
    @Override public Message receive(int timeout) throws IOException
    {
        // получить входной поток данных
        InputStream stream = socket.getInputStream(); 
    
        // проверить наличие данных
        if (timeout == 0) { if (stream.available() == 0) return null; }

        // указать величину тайм-аута
        else socket.setSoTimeout(timeout > 0 ? timeout : 0); 
        
        // выделить буфер для размера и типа
        byte[] encoded = new byte[8]; int length = 0; int type = 0; 

        // прочитать размер и тип данных 
        int size = stream.read(encoded); if (size != encoded.length) throw new IOException();

        // раскодировать размер и тип данных
        length |= ((encoded[0] & 0xFF)      ) | ((encoded[1] & 0xFF) <<  8); 
        length |= ((encoded[2] & 0xFF) << 16) | ((encoded[3] & 0xFF) << 24); 
        type   |= ((encoded[4] & 0xFF)      ) | ((encoded[5] & 0xFF) <<  8); 
        type   |= ((encoded[6] & 0xFF) << 16) | ((encoded[7] & 0xFF) << 24); 

        // выделить буфер требуемого размера
        if (length < 8) throw new IOException(); byte[] body = new byte[length - 8]; 

        // прочитать данные
        size = (body.length > 0) ? stream.read(body) : 0; 
        
        // проверить размер данных
        if (size != body.length) throw new IOException();

        // вернуть сообщение
        return new BinaryMessage<Integer>(type, body); 
    }
    ///////////////////////////////////////////////////////////////////////
    // Идентификатор процесса, использующего порт
    ///////////////////////////////////////////////////////////////////////
    public int getRemoteProcess() throws IOException
    {
        // получить строкое представление номера порта
        String strPort = String.format(":%1$d", remotePort()); 
            
        // создать список строк 
        List<String> lines = new ArrayList<String>(); 
        
        // для операционной системы Windows
        if (OS.INSTANCE instanceof OS.Windows) 
        {
            // перечислить процессы, взаимодействующие с портами
            for (String line : OS.INSTANCE.exec("netstat -nao"))
            {
                // проверить установку соединения
                if (!line.contains(" TCP ") || !line.contains(" ESTABLISHED ")) continue; 
                    
                // проверить наличие порта
                if (line.contains(strPort)) lines.add(line); 
            }
        }
        else {
            // перечислить процессы, взаимодействующие с портами
            for (String line : OS.INSTANCE.exec("netstat -napt"))
            {
                // проверить установку соединения
                if (!line.contains(" ESTABLISHED ")) continue; 

                // проверить наличие порта
                if (line.contains(strPort)) lines.add(line); 
            }
        }
        // для всех строк 
        for (String line : lines) 
        { 
            // создать список частей
            List<String> parts = new ArrayList<String>(); String str = line.trim();
                
            // найти позицию разделителя
            int start = 0; int index = str.indexOf(' ', start); 

            // пока не найдены все разделители
            for (; index >= 0; index = str.indexOf(' ', start = index + 1))
            {
                // извлечь отдельную часть
                parts.add(str.substring(start, index));
                
                // пропустить пробелы
                while (index + 1 < str.length() && str.charAt(index + 1) == ' ') index++; 
            }
            // извлечь отдельную часть
            if (start != str.length()) parts.add(str.substring(start)); 
            
            // для операционной системы Windows
            if (OS.INSTANCE instanceof OS.Windows) 
            {
                // проверить число компонентов
                if (parts.size() != 5) throw new IllegalStateException(); 
                
                // проверить наличие локального порта
                if (!parts.get(1).endsWith(strPort)) continue; 

                // раскодировать идентификатор процесса
                return Integer.parseInt(parts.get(4)); 
            }
            else {
                // проверить число компонентов
                if (parts.size() < 7) throw new IllegalStateException(); 

                // проверить наличие локального порта
                if (!parts.get(3).endsWith(strPort)) continue; 
                
                // найти позицию разделителя
                int pos = parts.get(6).indexOf('/'); if (pos >= 0)
                {
                    // раскодировать идентификатор процесса
                    return Integer.parseInt(parts.get(6).substring(0, pos)); 
                }
                // раскодировать идентификатор процесса
                else return Integer.parseInt(parts.get(6)); 
            }
        }
        return 0; 
    }
}
