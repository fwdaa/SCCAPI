package aladdin.pkcs11;
import aladdin.*; 
import aladdin.pkcs11.jni.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Модуль библиотеки PKCS11
///////////////////////////////////////////////////////////////////////////
public class Module extends RefObject
{
	// модуль и информация о нем
	private final Wrapper library; private final Info info; 
	
	// конструктор/деструктор
	public Module(String path) throws Exception, IOException 
	{
		// загрузить модуль PKCS11
		library = Wrapper.createInstance(path, API.CKF_OS_LOCKING_OK); 
		try { 
			// получить информацию о модуле
			info = new Info(library.C_GetInfo(), path); 
		}
		// обработать возможную ошибку
		catch (IOException e) { library.close(); throw e; }
	}
	@Override
	protected final void onClose() throws IOException
    { 
        // освободить выделенные ресурсы
        library.close(); super.onClose(); 
    } 
	///////////////////////////////////////////////////////////////////////////
	// Функции общего назначения
	///////////////////////////////////////////////////////////////////////////

	// имя модуля
	public final String path() { return info.path(); } 
		
	// информация о модуле
	public final Info info() { return info; }

	///////////////////////////////////////////////////////////////////////////
	// Управление устройствами
	///////////////////////////////////////////////////////////////////////////

	// получить список считывателей
	public final long[] getSlotList(boolean tokenPresent) throws Exception
	{
		// получить список считывателей
		return library.C_GetSlotList(tokenPresent); 
	}
	// получить информацию о считывателе
	public final SlotInfo getSlotInfo(long slotID) throws Exception
	{
		// получить информацию о считывателе
		try { return new SlotInfo(library.C_GetSlotInfo(slotID)); }
		
		// обработать возможную ошибку
		catch (IOException e) { throw new Exception(API.CKR_DEVICE_ERROR); }
	}
	// получить информацию о смарт-карте
	public final TokenInfo getTokenInfo(long slotID) throws Exception
	{
		// получить информацию о смарт-карте
		try { return new TokenInfo(library.C_GetTokenInfo(slotID)); }

		// обработать возможную ошибку
		catch (IOException e) { throw new Exception(API.CKR_DEVICE_ERROR); }
	}
	// дождаться события считывателя
	public final long waitForSlotEvent(long flags) throws Exception
	{
		// дождаться события считывателя
		return library.C_WaitForSlotEvent(flags, null); 
	}
	// инициализировать смарт-карту
	public final void initToken(long slotID, String pin, String label) 
		throws Exception
	{
		try { 
			// закодировать строки
			byte[] encodedPin   = pin  .getBytes("UTF-8"); 
			byte[] encodedLabel = label.getBytes("UTF-8"); 
		
			// инициализировать смарт-карту
			library.C_InitToken(slotID, encodedPin, encodedLabel);
		}
		// обработать возможную ошибку
		catch (UnsupportedEncodingException e) { throw new RuntimeException(e); }
	}
	// закрыть все сеансы со смарт-картой
	public final void closeAllSessions(long slotID) throws Exception
	{
		// закрыть все сеансы со смарт-картой
		library.C_CloseAllSessions(slotID);
	}
	///////////////////////////////////////////////////////////////////////////
	// Управление сеансами
	///////////////////////////////////////////////////////////////////////////

	// создать сеанс
	public final long openSession(long slotID, 
        long flags, Object pApplication, Notify notify) throws Exception
	{
        // указать режим открытия
        flags |= API.CKF_SERIAL_SESSION; 
        
		// создать сеанс
		return library.C_OpenSession(slotID, flags, pApplication, notify); 
	}
	// получить информацию о сеансе
	public final SessionInfo getSessionInfo(long hSession) 
		throws Exception
	{
		// получить информацию о сеансе
		return new SessionInfo(library.C_GetSessionInfo(hSession)); 
	}
	// закрыть сеанс
	public final void closeSession(long hSession) throws Exception
	{
		// закрыть сеанс
		library.C_CloseSession(hSession);
	}
	// выполнить аутентификацию смарт-карты
	public final void login(long hSession, long userType, String pin) throws Exception
	{
		try {
			// закодировать строку
			byte[] encodedPin = pin.getBytes("UTF-8"); 

			// выполнить аутентификацию смарт-карты
			library.C_Login(hSession, userType, encodedPin);
		}
		// обработать возможную ошибку
		catch (UnsupportedEncodingException e) { throw new RuntimeException(e); }
	}
	// отменить аутентификацию смарт-карты
	public final void logout(long hSession) throws Exception
	{
		// отменить аутентификацию смарт-карты
		library.C_Logout(hSession);
	}
	// установить первоначальный пин-код
	public final void initPIN(long hSession, String pin) throws Exception
	{
		try {
			// закодировать строку
			byte[] encodedPin = pin.getBytes("UTF-8"); 

			// установить первоначальный пин-код
			library.C_InitPIN(hSession, encodedPin);
		}
		// обработать возможную ошибку
		catch (UnsupportedEncodingException e) { throw new RuntimeException(e); }
	}
	// изменить пин-код
	public final void setPIN(long hSession, 
        String pinOld, String pinNew) throws Exception
	{
		try {
			// закодировать строки
			byte[] encodedPinOld = pinOld.getBytes("UTF-8"); 
			byte[] encodedPinNew = pinNew.getBytes("UTF-8");

			// изменить пин-код
			library.C_SetPIN(hSession, encodedPinOld, encodedPinNew);
		}
		// обработать возможную ошибку
		catch (UnsupportedEncodingException e) { throw new RuntimeException(e); }
	}
	///////////////////////////////////////////////////////////////////////////
	// Управление алгоритмами
	///////////////////////////////////////////////////////////////////////////

	// получить список алгоритмов
	public final long[] getAlgorithmList(long slotID) throws Exception
	{
		// получить список алгоритмов
		return library.C_GetMechanismList(slotID); 
	}
	// получить информацию об алгоритме
	public final MechanismInfo getAlgorithmInfo(long slotID, long type)
		throws Exception
	{
		return new MechanismInfo(library.C_GetMechanismInfo(slotID, type)); 
	}
	///////////////////////////////////////////////////////////////////////////
	// Генерация случайных данных
	///////////////////////////////////////////////////////////////////////////

	// установить стартовое значение для генератора 
	public final void seedRandom(long hSession, byte[] in, int inOfs, int inLen)
		throws Exception
	{
		// установить стартовое значение для генератора 
		library.C_SeedRandom(hSession, in, inOfs, inLen);
	}
	// сгенерировать случайные данные
	public final void generateRandom(long hSession, byte[] out, int outOfs, int outLen)
		throws Exception
	{
		// сгенерировать случайные данные
		library.C_GenerateRandom(hSession, out, outOfs, outLen);
	}
	///////////////////////////////////////////////////////////////////////////
	// Управление объектами
	///////////////////////////////////////////////////////////////////////////

	// создать объект
	public final long createObject(long hSession, CK_ATTRIBUTE[] attributes)
		throws Exception
	{
        // проверить указание атрибутов
        if (attributes == null) attributes = new CK_ATTRIBUTE[0]; 
        
		// для всех атрибутов 
		for (CK_ATTRIBUTE attribute : attributes)
		{
			// проверить наличие значения
			if (attribute.value != null) continue; 
				
			// при ошибке выбросить исключение
			throw new aladdin.pkcs11.Exception(API.CKR_KEY_UNEXTRACTABLE);
		}
		// создать объект
		return library.C_CreateObject(hSession, attributes); 
	}
	// скопировать объект
	public final long copyObject(long hSession, long hObject, CK_ATTRIBUTE[] attributes)
		throws Exception
	{
        // проверить указание атрибутов
        if (attributes == null) attributes = new CK_ATTRIBUTE[0]; 
        
		// скопировать объект
		return library.C_CopyObject(hSession, hObject, attributes); 
	}
	// закрыть объект
	public final void destroyObject(long hSession, long hObject)
		throws Exception
	{
		// закрыть объект
		library.C_DestroyObject(hSession, hObject);
	}
	// найти объекты
	public final long[] findObjects(long hSession, CK_ATTRIBUTE[] attributes) 
		throws Exception
	{
        // проверить указание атрибутов
        if (attributes == null) attributes = new CK_ATTRIBUTE[0]; 
        
		// инициализировать поиск объектов
		library.C_FindObjectsInit(hSession, attributes);
		try {
			// инициадизировать список идентификаторов
			long[] objs = new long[0]; long[] partObjs;
			do {
				// найти идентификаторы объектов с указанными атрибутами
				int count = objs.length; partObjs = library.C_FindObjects(hSession, 1024); 

				// выделить память для новых идентификаторов
				long[] temp = new long[count + partObjs.length]; 
				
				// скопировать ранее полученные элементы
				System.arraycopy(objs, 0, temp, 0, count); objs = temp; 

				// скопировать новые элементы
				System.arraycopy(partObjs, 0, objs, count, partObjs.length); 
			}
			// продолжать до окончания поиска
			while (partObjs.length == 1024); return objs;
		}
		// остановить поиск объектов
		finally { library.C_FindObjectsFinal(hSession); }
	}
	// получить значение атрибутов
	public final CK_ATTRIBUTE[] getAttributes(
        long hSession, long hObject, CK_ATTRIBUTE[] attributes) throws Exception
	{
        // проверить указание атрибутов
        if (attributes == null) attributes = new CK_ATTRIBUTE[0]; 
        try {
            // выделить буфер требуемого размера
            CK_ATTRIBUTE[] attrs = new CK_ATTRIBUTE[attributes.length]; 

            // для всех атрибутов
            for (int i = 0; i < attributes.length; i++)
            {
                // указать тип атрибута
                attrs[i] = new CK_ATTRIBUTE(attributes[i].type, attributes[i].valueClass); 
            }
            // получить значение атрибутов
            library.C_GetAttributeValue(hSession, hObject, attrs); return attrs; 
        }
        catch (Throwable e) 
        {
            // скопировать аттрибуты
            attributes = attributes.clone(); CK_ATTRIBUTE[] attrs = new CK_ATTRIBUTE[1]; 
            
            // для всех атрибутов
            for (int i = 0; i < attributes.length; i++)
            {
                // указать требуемый атрибут
                attrs[0] = new CK_ATTRIBUTE(attributes[i].type, attributes[i].valueClass); 

                // при отсутствии значения по умолчанию
                if (attributes[i].value == null) 
                {
                    // получить значение атрибута
                    library.C_GetAttributeValue(hSession, hObject, attrs); 

                    // скопировать атрибут
                    attributes[i] = new CK_ATTRIBUTE(attributes[i].type, attrs[0].value); 
                }
                else try { 
                    // получить значение атрибута
                    library.C_GetAttributeValue(hSession, hObject, attrs); 

                    // скопировать атрибут
                    attributes[i] = new CK_ATTRIBUTE(attributes[i].type, attrs[0].value); 
                }
                catch (Throwable ex) {}
            }
        }
        return attributes; 
	}
	// установить значение атрибутов
	public final void setAttributes(long hSession, 
        long hObject, CK_ATTRIBUTE[] attributes) throws Exception
	{
        // проверить указание атрибутов
        if (attributes == null) attributes = new CK_ATTRIBUTE[0]; 
        
		// установить значение атрибутов
		library.C_SetAttributeValue(hSession, hObject, attributes); 
	}
	// определить размер объекта на смарт-карте
	public final int getObjectSize(long hSession, long hObject)
		throws Exception
	{
		// определить размер объекта на смарт-карте
		return (int)library.C_GetObjectSize(hSession, hObject); 
	}
	///////////////////////////////////////////////////////////////////////////
	// Управление ключами
	///////////////////////////////////////////////////////////////////////////

	// создать симметричный ключ
	public final long generateKey(long hSession, CK_MECHANISM mechanism, 
		CK_ATTRIBUTE[] attributes) throws Exception
	{
        // проверить указание атрибутов
        if (attributes == null) attributes = new CK_ATTRIBUTE[0]; 
        
		// создать симметричный ключ
		return library.C_GenerateKey(hSession, mechanism, attributes); 
	}
	// создать пару ассиметричных ключей
	public final long[] generateKeyPair(long hSession, CK_MECHANISM mechanism, 
		CK_ATTRIBUTE[] publicAttributes, CK_ATTRIBUTE[] privateAttributes)
		throws Exception
	{
        // проверить указание атрибутов
        if (publicAttributes  == null) publicAttributes  = new CK_ATTRIBUTE[0]; 
        if (privateAttributes == null) privateAttributes = new CK_ATTRIBUTE[0]; 
        
		// создать пару ассиметричных ключей
		return library.C_GenerateKeyPair(hSession, 
			mechanism, publicAttributes, privateAttributes);
	}
	///////////////////////////////////////////////////////////////////////////
	// Хэширование данных
	///////////////////////////////////////////////////////////////////////////

	// инициализировать алгоритм хэширования
	public final void digestInit(long hSession, CK_MECHANISM mechanism)
		throws Exception
	{
		// инициализировать алгоритм хэширования
		library.C_DigestInit(hSession, mechanism);
	}
	// захэшировать данные
	public final void digestUpdate(long hSession, byte[] data, int dataOff, int dataLen)
		throws Exception
	{
		// захэшировать данные
		library.C_DigestUpdate(hSession, data, dataOff, dataLen);
	}
	// захэшировать значение ключа
	public final void digestKey(long hSession, long hKey)
		throws Exception
	{
		// захэшировать значение ключа
		library.C_DigestKey(hSession, hKey);
	}
	// получить хэш-значение
	public final int digestFinal(long hSession, byte[] buf, int bufOff)
		throws Exception
	{
		// получить хэш-значение
		return library.C_DigestFinal(hSession, buf, bufOff);
	}
	///////////////////////////////////////////////////////////////////////////
	// Выработка имитовставки и подписи данных
	///////////////////////////////////////////////////////////////////////////

	// инициализировать алгоритм имитовставки или подписи данных
	public final void signInit(long hSession, CK_MECHANISM mechanism, long hKey)
		throws Exception
	{
		// инициализировать алгоритм имитовставки или подписи данных
		library.C_SignInit(hSession, mechanism, hKey);
	}
	// обработать данные
	public final void signUpdate(long hSession, byte[] data, int dataOff, int dataLen)
		throws Exception
	{
		// обработать данные
		library.C_SignUpdate(hSession, data, dataOff, dataLen);
	}
	// получить имитовставку или подпись данных
	public final int signFinal(long hSession, byte[] buff, int bufOff)
		throws Exception
	{
		// получить имитовставку или подпись данных
		return library.C_SignFinal(hSession, buff, bufOff);
	}
	// получить имитовставку или подпись данных
	public final byte[] sign(long hSession, byte[] data, int dataOff, int dataLen)
		throws Exception
	{
		// определить требуемый размер буфера
		int bufferLen = library.C_Sign(hSession, data, dataOff, dataLen, null, 0); 
		
		// выделить буфер требуемого размера
		byte[] buffer = new byte[bufferLen]; 
		
		// получить имитовставку или подпись данных
		bufferLen = library.C_Sign(hSession, data, dataOff, dataLen, buffer, 0); 
		
		// проверить размер буфера
		if (buffer.length == bufferLen) return buffer; 
		
		// выделить буфер требуемого размера
		byte[] copy = new byte[bufferLen]; 
		
		// скопировать результат
		System.arraycopy(buffer, 0, copy, 0, bufferLen); return copy; 
	}
	///////////////////////////////////////////////////////////////////////////
	// Проверка имитовставки и подписи данных
	///////////////////////////////////////////////////////////////////////////

	// инициализировать алгоритм имитовставки или проверки подписи
	public final void verifyInit(long hSession, CK_MECHANISM mechanism, long hKey)
		throws Exception
	{
		// инициализировать алгоритм имитовставки или проверки подписи
		library.C_VerifyInit(hSession, mechanism, hKey);
	}
	// обработать данные
	public final void verifyUpdate(long hSession, byte[] data, int dataOff, int dataLen)  
		throws Exception
	{
		// обработать данные
		library.C_VerifyUpdate(hSession, data, dataOff, dataLen);
	}
	// проверить имитовставку или подпись данных
	public final void verifyFinal(long hSession, byte[] signature)
		throws Exception
	{
		// проверить имитовставку или подпись данных
		library.C_VerifyFinal(hSession, signature, 0, signature.length);
	}
	// проверить имитовставку или подпись данных
	public final void verify(long hSession, byte[] data, int dataOff, int dataLen, byte[] signature)
		throws Exception
	{
		// проверить имитовставку или подпись данных
		library.C_Verify(hSession, data, dataOff, dataLen, signature, 0, signature.length);
	}
	///////////////////////////////////////////////////////////////////////////
	// Шифрование данных
	///////////////////////////////////////////////////////////////////////////

	// инициализировать алгоритм зашифрования
	public final void encryptInit(long hSession, CK_MECHANISM mechanism, long hKey)
		throws Exception
	{
		// инициализировать алгоритм зашифрования
		library.C_EncryptInit(hSession, mechanism, hKey);
	}
	// зашифровать данные
	public final int encryptUpdate(long hSession, byte[] data, 
		int dataOff, int dataLen, byte[] buffer, int bufferOff)
		throws Exception
	{
		// зашифровать данные
		return library.C_EncryptUpdate(hSession, data, dataOff, dataLen, buffer, bufferOff); 
	}
	// завершить зашифрование данных
	public final int encryptFinal(long hSession, byte[] buffer, int bufferOff)
		throws Exception
	{
		// завершить зашифрование данных
		return library.C_EncryptFinal(hSession, buffer, bufferOff); 
	}
	// зашифровать данные
	public final byte[] encrypt(long hSession, byte[] data, int dataOff, int dataLen)
		throws Exception
	{
		// определить требуемый размер буфера
		int bufferLen = library.C_Encrypt(hSession, data, dataOff, dataLen, null, 0); 
		
		// выделить буфер требуемого размера
		byte[] buffer = new byte[bufferLen]; 
		
		// зашифровать данные
		bufferLen = library.C_Encrypt(hSession, data, dataOff, dataLen, buffer, 0); 
		
		// проверить размер буфера
		if (buffer.length == bufferLen) return buffer; 
		
		// выделить буфер требуемого размера
		byte[] copy = new byte[bufferLen]; 
		
		// скопировать результат
		System.arraycopy(buffer, 0, copy, 0, bufferLen); return copy; 
	}
	// инициализировать алгоритм расшифрования
	public final void decryptInit(long hSession, CK_MECHANISM mechanism, long hKey)
		throws Exception
	{
		// инициализировать алгоритм расшифрования
		library.C_DecryptInit(hSession, mechanism, hKey);
	}
	// расшифровать данные
	public final int decryptUpdate(long hSession, byte[] data, 
		int dataOff, int dataLen, byte[] buffer, int bufferOff)
		throws Exception
	{
		// расшифровать данные
		return library.C_DecryptUpdate(hSession, data, dataOff, dataLen, buffer, bufferOff); 
	}
	// завершить расшифрование данных
	public final int decryptFinal(long hSession, byte[] buffer, int bufferOff)
		throws Exception
	{
		// завершить расшифрование данных
		return library.C_DecryptFinal(hSession, buffer, bufferOff); 
	}
	// расшифровать данные
	public final byte[] decrypt(long hSession, byte[] data, int dataOff, int dataLen)
		throws Exception
	{
		// определить требуемый размер буфера
		int bufferLen = library.C_Decrypt(hSession, data, dataOff, dataLen, null, 0); 
		
		// выделить буфер требуемого размера
		byte[] buffer = new byte[bufferLen]; 
		
		// расшифровать данные
		bufferLen = library.C_Decrypt(hSession, data, dataOff, dataLen, buffer, 0); 
		
		// проверить размер буфера
		if (buffer.length == bufferLen) return buffer; 
		
		// выделить буфер требуемого размера
		byte[] copy = new byte[bufferLen]; 
		
		// скопировать результат
		System.arraycopy(buffer, 0, copy, 0, bufferLen); return copy; 
	}
	///////////////////////////////////////////////////////////////////////////
	// Шифрование ключа
	///////////////////////////////////////////////////////////////////////////

	// зашифровать ключ
	public final byte[] wrapKey(long hSession, CK_MECHANISM mechanism, 
        long hWrapKey, long hKey) throws Exception
	{
		// определить требуемый размер буфера
		int bufferLen = library.C_WrapKey(
            hSession, mechanism, hWrapKey, hKey, null, 0
        ); 
		// выделить буфер требуемого размера
		byte[] buffer = new byte[bufferLen]; 
		
		// зашифровать ключ
		bufferLen = library.C_WrapKey(
            hSession, mechanism, hWrapKey, hKey, buffer, 0
        ); 
		// проверить размер буфера
		if (buffer.length == bufferLen) return buffer; 
		
		// выделить буфер требуемого размера
		byte[] copy = new byte[bufferLen]; 
		
		// скопировать результат
		System.arraycopy(buffer, 0, copy, 0, bufferLen); return copy; 
	}
	// расшифровать ключ
	public final long unwrapKey(long hSession, CK_MECHANISM mechanism, 
		long hWrapKey, byte[] data, CK_ATTRIBUTE[] attributes) throws Exception
	{
        // проверить указание атрибутов
        if (attributes == null) attributes = new CK_ATTRIBUTE[0]; 
        
		// расшифровать ключ
		return library.C_UnwrapKey(hSession, 
            mechanism, hWrapKey, data, 0, data.length, attributes
        );
	}
	///////////////////////////////////////////////////////////////////////////
	// Наследование ключа
	///////////////////////////////////////////////////////////////////////////
	public final long deriveKey(long hSession, CK_MECHANISM mechanism, 
		long hBaseKey, CK_ATTRIBUTE[] attributes) throws Exception
	{
        // проверить указание атрибутов
        if (attributes == null) attributes = new CK_ATTRIBUTE[0]; 
        
		// унаследовать ключ
		return library.C_DeriveKey(hSession, mechanism, hBaseKey, attributes); 
	}
}
