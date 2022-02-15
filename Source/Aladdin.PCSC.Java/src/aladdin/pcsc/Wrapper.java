package aladdin.pcsc;
import aladdin.*; 
import java.io.*;
import java.security.*;

public class Wrapper extends Disposable
{
    // адрес глобальных данных для библиотеки поддержки
    private long pNativeData; 
    static {
        // cannot use LoadLibraryAction because that would make the native
        // library available to the bootclassloader, but we run in the
        // extension classloader.
        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            @Override
            public Object run()   
            {
                // определить URL-путь к файлу с классом
                CodeSource codeSource = Wrapper.class.getProtectionDomain().getCodeSource(); 

                // определить файл с классом
                File jarFile = new File(codeSource.getLocation().getPath());                
                
                // определить каталог класса
                String jarDir = jarFile.getParentFile().getPath();
                
                // указать разделитель
                if (!jarDir.endsWith(File.separator)) jarDir += File.separator; 
                
                // загрузить библиотеку поддержки
                System.load(jarDir + "pcscjni.dll"); return null;
            }
        });
    }
    // инициализировать модуль
    private native void init() throws IOException;

    // освободить выделенные ресурсы модуля
    private native void done();

    // конструктор
    Wrapper() throws IOException { init(); }
    // деструктор
    @Override protected final void onClose() throws IOException
    { 
        // освободить выделенные ресурсы
        done(); super.onClose(); 
    } 
    // создать контекст
    public native long establishContext(int scope) throws Exception;
    // закрыть контекст
    public native void releaseContext(long hContext) throws Exception;

    // перечислить группы считывателей
    public native String[] listReaderGroups(long hContext) throws Exception;
    // перечислить считыватели
    public native String[] listReaders(long hContext, String[] groups) throws Exception;

    // дождаться события смарт-карт
    public native int getStatusChange(long hContext, 
        int timeout, ReaderAndState[] readerStates) throws Exception;
    // отменить ожидание события смарт-карт
    public native void cancelContext(long hContext)throws Exception; 

    // открыть считыватель и смарт-карту
    public native long connect(long hContext, 
        String reader, int shareMode, int[] protocols) throws Exception;
    // заново открыть считыватель и смарт-карту
    public native void reconnect(long hCard, 
        int shareMode, int[] protocols, int dwInitialization) throws Exception;
    // закрыть считыватель и смарт-карту
    public native void disconnect(long hCard, int closeMode) throws Exception;

    // получить состояние считывателя и смарт-карты
    public native void getReaderStatus(long hCard, ReaderStatus status) throws Exception; 

    // получить атрибут считывателя
    public native byte[] getReaderAttribute(long hCard, int attrId) throws Exception;
    // установить атрибут считывателя
    public native void setReaderAttribute(long hCard, int attrId, byte[] attr) throws Exception;

    // начать транзакцию со смарт-картой
    public native void beginTransaction(long hCard) throws Exception; 
    // завершить транзакцию со смарт-картой
    public native void endTransaction(long hCard, int dwCloseMode) throws Exception; 

    // передать команду считывателю
    public native int control(long hCard, 
        int controlCode, byte[] inBuffer, byte[] outBuffer) throws Exception; 
    
    // передать команду смарт-карте
    public native int transmit(long hCard, 
        int protocol, byte[] sendBuffer, byte[] recvBuffer) throws Exception;
}
