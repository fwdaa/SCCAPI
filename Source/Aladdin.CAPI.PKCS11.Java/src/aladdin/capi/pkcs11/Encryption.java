package aladdin.capi.pkcs11;
import aladdin.*; 
import aladdin.capi.*; 
import aladdin.pkcs11.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм зашифрования данных 
///////////////////////////////////////////////////////////////////////////////
public class Encryption extends Transform
{
	private final Cipher      cipher;		// алгоритм шифрования
	private final PaddingMode padding;      // режим дополнения
	private final ISecretKey  key;          // ключ шифрования
	private Session           session;      // используемый сеанс

	// конструктор
	public Encryption(Cipher cipher, PaddingMode padding, ISecretKey key)
    {
        // сохранить переданные параметры
        this.cipher = RefObject.addRef(cipher); this.key = RefObject.addRef(key);

        // инициализировать параметры
        this.padding = padding; session = null; 
    }
	// деструктор
    @Override protected void onClose() throws IOException   
    { 
        // закрыть сеанс
        if (session != null) session.close(); 

        // освободить выделенные ресурсы
        RefObject.release(key); RefObject.release(cipher); super.onClose(); 
    }
	// размер блока
    @Override public int blockSize() { return cipher.blockSize(); }

	// режим дополнения
    @Override public PaddingMode padding() { return padding; }
    
	// инициализировать алгоритм
    @Override
	public void init() throws IOException
    {
        // указать дополнительный атрибут ключа
        Attribute[] keyAttributes = new Attribute[] {
            new Attribute(API.CKA_ENCRYPT, API.CK_TRUE)
        }; 
        // получить атрибуты ключа
        keyAttributes = Attribute.join(
            keyAttributes, cipher.getKeyAttributes(key.length())
        );  
        // открыть новый сеанс
        session = cipher.applet().openSession(API.CKS_RO_PUBLIC_SESSION);
        try {
            // получить параметры алгоритма
            Mechanism parameters = cipher.getParameters(session); 
            
            // преобразовать тип ключа
            SessionObject sessionKey = cipher.applet().provider().
                toSessionObject(session, key, keyAttributes); 
            
            // инициализировать алгоритм
            session.encryptInit(parameters, sessionKey.handle());
        }
        // обработать возможную ошибку
        catch (Throwable e) { session.close(); session = null; throw e; }
    }
	// преобразовать данные
    @Override
	public int update(byte[] data, int dataOff, 
        int dataLen, byte[] buf, int bufOff) throws IOException
    {
        // проверить наличие данных
        if (dataLen == 0) return 0; 
        
        // зашифровать данные
        return session.encryptUpdate(data, dataOff, dataLen, buf, bufOff); 
    }
    // завершить преобразование
    @Override
	public int finish(byte[] data, int dataOff, 
        int dataLen, byte[] buf, int bufOff) throws IOException
    {
        // зашифровать данные
        int total = session.encryptUpdate(data, dataOff, dataLen, buf, bufOff); 

        // завершить зашифрование данных
        total += session.encryptFinal(buf, bufOff + total); 

        // закрыть сеанс
        session.close(); session = null; return total; 
    }
}; 
