package aladdin.capi.pkcs11;
import aladdin.*; 
import aladdin.capi.*;
import aladdin.pkcs11.*; 
import aladdin.pkcs11.Exception; 
import aladdin.pkcs11.jni.*;
import aladdin.util.*; 
import java.io.*; 
import java.util.*;

///////////////////////////////////////////////////////////////////////////////
// Сеанс взаимодействия с устройством
///////////////////////////////////////////////////////////////////////////////
public class Session extends RefObject
{
	private final Module module;   // модуль библиотеки PKCS#11
	private final long	 slotID;   // идентификатор считывателя
	private final long	 hSession; // описатель сеанса

	// конструктор
	public Session(Module module, long slotID, 
        long mode, Notify notify, Object pApplication) throws Exception
	{
		this.module	= module;	// модуль библиотеки PKCS#11
		this.slotID	= slotID;	// идентификатор считывателя
        
		// создать новый сеанс
		hSession = module.openSession(slotID, mode, pApplication, notify);
	}
	@Override
	protected void onClose() throws IOException   
    { 
		// закрыть сеанс
		module.closeSession(hSession); super.onClose();
	} 
	public final Module	module() { return module;   }
	public final long	slotID() { return slotID;   }
	public final long	handle() { return hSession; }

	///////////////////////////////////////////////////////////////////////////
	// Аутентификация пользователя
	///////////////////////////////////////////////////////////////////////////
	public final SessionInfo getSessionInfo() throws Exception
	{ 
		// получить информацию о сеансе
		return module.getSessionInfo(hSession); 
	}
	// установить пин-код
	public final void login(long userType, String password) throws Exception
	{ 
		// установить пин-код
		module.login(hSession, userType, password); 
	}
	// сбросить аутентификацию
	public final void logout() throws Exception { module.logout(hSession); }
    
	// установить/изменить пин-код для CKU_USER от имени администратора
	public final void setUserPassword(String password) throws Exception
	{
		// установить/изменить пин-код
		module.initPIN(hSession, password); 
	}
	// изменить пин-код текущего пользователя
	public final void changePassword(
        String passwordOld, String passwordNew) throws Exception
	{
		// изменить пин-код текущего пользователя
		module.setPIN(hSession, passwordOld, passwordNew); 
	}
	///////////////////////////////////////////////////////////////////////////
	// Генерация случайных данных
	///////////////////////////////////////////////////////////////////////////

	// установить стартовое значение для генератора 
	public final void seedRandom(byte[] in, int inOfs, int inLen) throws Exception			
	{
		// установить стартовое значение для генератора 
		module.seedRandom(hSession, in, inOfs, inLen); 
	}
	// сгенерировать случайные данные
	public final void generateRandom(byte[] out, int outOfs, int outLen) throws Exception			
	{
		// сгенерировать случайные данные
		module.generateRandom(hSession, out, outOfs, outLen); 
	}
	///////////////////////////////////////////////////////////////////////////
	// Управление ключами
	///////////////////////////////////////////////////////////////////////////

	// создать симметричный ключ
	public final SessionObject generateKey(Mechanism parameters, 
		Attribute[] attributes) throws Exception			
	{
        // преобразовать атрибуты
        CK_ATTRIBUTE[] attrs = Attribute.convert(attributes); 
        
		// создать симметричный ключ
		long hObject = module.generateKey(hSession, parameters.convert(), attrs);  
		
		// вернуть созданный объект
		return new SessionObject(this, hObject); 
    }
    // сгенерировать пару ключей
	public final SessionObject[] generateKeyPair(Mechanism parameters,
        KeyUsage keyUsage, Attribute[] publicAttributes, 
        Attribute[] privateAttributes) throws IOException
    {
        // создать списки атрибутов
        List<Attribute> requiredPublicAttributes  = new ArrayList<Attribute>(
            Arrays.asList(publicAttributes)
        ); 
        List<Attribute> requiredPrivateAttributes = new ArrayList<Attribute>(
            Arrays.asList(privateAttributes)
        ); 
        // указать классы объектов
        requiredPublicAttributes .add(new Attribute(API.CKA_CLASS, API.CKO_PUBLIC_KEY ));
        requiredPrivateAttributes.add(new Attribute(API.CKA_CLASS, API.CKO_PRIVATE_KEY));

        // в зависимости от использования ключа
        if ((keyUsage.containsAny(KeyUsage.DIGITAL_SIGNATURE | 
            KeyUsage.CERTIFICATE_SIGNATURE | KeyUsage.CRL_SIGNATURE | KeyUsage.NON_REPUDIATION))) 
        {
            // указать значения атрибутов
            requiredPrivateAttributes.add(new Attribute(API.CKA_SIGN   , API.CK_TRUE));  
            requiredPublicAttributes .add(new Attribute(API.CKA_VERIFY , API.CK_TRUE));  
        }
        // в зависимости от использования ключа
        if ((keyUsage.contains(KeyUsage.KEY_ENCIPHERMENT))) 
        {
            // указать значения атрибутов
            requiredPrivateAttributes.add(new Attribute(API.CKA_UNWRAP, API.CK_TRUE));  
            requiredPublicAttributes .add(new Attribute(API.CKA_WRAP  , API.CK_TRUE)); 
        }
        if ((keyUsage.contains(KeyUsage.KEY_AGREEMENT))) 
        {
            // указать значения атрибутов
            requiredPrivateAttributes.add(new Attribute(API.CKA_DERIVE , API.CK_TRUE));  
            requiredPublicAttributes .add(new Attribute(API.CKA_DERIVE , API.CK_TRUE));  
        }
		// создать необязательные атрибуты
		List<Attribute> optionalPublicAttributes  = new ArrayList<Attribute>(); 
		List<Attribute> optionalPrivateAttributes = new ArrayList<Attribute>(); 
        
        // в зависимости от использования ключа
        if ((keyUsage.contains(KeyUsage.DATA_ENCIPHERMENT))) 
        {
            // указать значения атрибутов
            optionalPrivateAttributes.add(new Attribute(API.CKA_DECRYPT, API.CK_TRUE)); 
            optionalPublicAttributes .add(new Attribute(API.CKA_ENCRYPT, API.CK_TRUE));  
        }
		// создать список атрибутов
		List<Attribute> pubAttributes  = new ArrayList<Attribute>(); 
		List<Attribute> privAttributes = new ArrayList<Attribute>(); 
        
		// указать обязательные атрибуты
		pubAttributes .addAll(requiredPublicAttributes ); 
		privAttributes.addAll(requiredPrivateAttributes); 
        
		// указать необязательные атрибуты
		pubAttributes .addAll(optionalPublicAttributes ); 
		privAttributes.addAll(optionalPrivateAttributes); 
        
		// выделить память для результата
		SessionObject[] objects = new SessionObject[2]; 
        try { 
            // преобразовать атрибуты
            CK_ATTRIBUTE[] publicAttrs  = Attribute.convert(
                pubAttributes.toArray(new Attribute[pubAttributes.size()])
            ); 
            // преобразовать атрибуты
            CK_ATTRIBUTE[] privateAttrs = Attribute.convert(
                privAttributes.toArray(new Attribute[privAttributes.size()])
            ); 
            // создать пару ассиметричных ключей
            long[] hObjects = module.generateKeyPair(
                hSession, parameters.convert(), publicAttrs, privateAttrs); 

            // вернуть созданные объекты
            objects[0] = new SessionObject(this, hObjects[0]); 
            objects[1] = new SessionObject(this, hObjects[1]); return objects; 
        }
        catch (aladdin.pkcs11.Exception e)
        {
            // проверить код ошибки
            if (e.getErrorCode() != API.CKR_ATTRIBUTE_TYPE_INVALID) throw e; 

			// проверить наличие необязательных атрибутов
			if (optionalPublicAttributes .isEmpty() && 
				optionalPrivateAttributes.isEmpty()) throw e; 

            // преобразовать атрибуты
            CK_ATTRIBUTE[] publicAttrs  = Attribute.convert(
                requiredPublicAttributes.toArray(
                    new Attribute[requiredPublicAttributes.size()]
            )); 
            CK_ATTRIBUTE[] privateAttrs = Attribute.convert(
                requiredPrivateAttributes.toArray(
                    new Attribute[requiredPrivateAttributes.size()]
            )); 
            // создать пару ассиметричных ключей
            long[] hObjects = module.generateKeyPair(
                hSession, parameters.convert(), publicAttrs, privateAttrs); 

            // вернуть созданные объекты
            objects[0] = new SessionObject(this, hObjects[0]); 
            objects[1] = new SessionObject(this, hObjects[1]); return objects; 
        }
    }
	///////////////////////////////////////////////////////////////////////////
	// Управление объектами
	///////////////////////////////////////////////////////////////////////////

    // сгенерировать пару ключей
	public final SessionObject[] createKeyPair(KeyUsage keyUsage, 
        Attribute[] publicAttributes, Attribute[] privateAttributes) throws IOException
    {
        // создать списки атрибутов
        List<Attribute> pubAttributes  = new ArrayList<Attribute>(
            Arrays.asList(publicAttributes)
        ); 
        List<Attribute> privAttributes = new ArrayList<Attribute>(
            Arrays.asList(privateAttributes)
        ); 
        // в зависимости от использования ключа
        if ((keyUsage.containsAny(KeyUsage.DIGITAL_SIGNATURE | 
            KeyUsage.CERTIFICATE_SIGNATURE | KeyUsage.CRL_SIGNATURE | KeyUsage.NON_REPUDIATION))) 
        {
            // указать значения атрибутов
            privAttributes.add(new Attribute(API.CKA_SIGN   , API.CK_TRUE));  
            pubAttributes .add(new Attribute(API.CKA_VERIFY , API.CK_TRUE));  
        }
        // в зависимости от использования ключа
        if ((keyUsage.contains(KeyUsage.KEY_ENCIPHERMENT))) 
        {
            // указать значения атрибутов
            pubAttributes .add(new Attribute(API.CKA_WRAP  , API.CK_TRUE)); 
            privAttributes.add(new Attribute(API.CKA_UNWRAP, API.CK_TRUE));  
        }
        if ((keyUsage.contains(KeyUsage.KEY_AGREEMENT))) 
        {
            // указать значения атрибутов
            privAttributes.add(new Attribute(API.CKA_DERIVE , API.CK_TRUE));  
            pubAttributes .add(new Attribute(API.CKA_DERIVE , API.CK_TRUE));  
        }
        // сохранить списки атрибутов
        publicAttributes  = pubAttributes .toArray(new Attribute[pubAttributes .size()]); 
        privateAttributes = privAttributes.toArray(new Attribute[privAttributes.size()]);
        
		// создать необязательные атрибуты
		List<Attribute> optionalPubAttributes  = new ArrayList<Attribute>(); 
		List<Attribute> optionalPrivAttributes = new ArrayList<Attribute>(); 

        // в зависимости от использования ключа
        if ((keyUsage.contains(KeyUsage.DATA_ENCIPHERMENT))) 
        {
            // указать значения атрибутов
            optionalPubAttributes .add(new Attribute(API.CKA_ENCRYPT, API.CK_TRUE));  
            optionalPrivAttributes.add(new Attribute(API.CKA_DECRYPT, API.CK_TRUE)); 
        }
        // выделить буфер требуемого размера
        SessionObject[] objs = new SessionObject[2]; 
            
        // сохранить открытый ключ на смарт-карту
        objs[0] = createObject(publicAttributes, 
            optionalPubAttributes.toArray(new Attribute[optionalPubAttributes.size()])
        ); 
        try { 
            // сохранить личный ключ на смарт-карту
            objs[1] = createObject(privateAttributes, 
                optionalPrivAttributes.toArray(new Attribute[optionalPrivAttributes.size()])
            ); 
        }
        // при ошибке удалить личный ключ
        catch (IOException e) { destroyObject(objs[0]); throw e; } return objs; 
    }
	// создать объект
	public final SessionObject createObject(
        Attribute[] requiredAttributes, Attribute[] optionalAttributes)
		throws Exception			
	{
        // проверить наличие атрибутов
        if (requiredAttributes == null) requiredAttributes = new Attribute[0]; 
        if (optionalAttributes == null) optionalAttributes = new Attribute[0]; 
        
		// создать список атрибутов
		List<Attribute> attributes = new ArrayList<Attribute>(); 

		// объединить атрибуты
        attributes.addAll(Arrays.asList(requiredAttributes)); 
		attributes.addAll(Arrays.asList(optionalAttributes)); 
        try {
            // преобразовать атрибуты
            CK_ATTRIBUTE[] attrs = Attribute.convert(
                attributes.toArray(new Attribute[attributes.size()])
            ); 
            // создать объект с указанными атрибутами
            long hObject = module.createObject(hSession, attrs);  

            // вернуть созданный объект
            return new SessionObject(this, hObject); 
        }
        catch (aladdin.pkcs11.Exception e)
        {
            // проверить код ошибки
            if (e.getErrorCode() != API.CKR_ATTRIBUTE_TYPE_INVALID) throw e; 
            
    		// проверить наличие необязательных атрибутов
			if (optionalAttributes.length == 0) throw e; 

            // преобразовать атрибуты
            CK_ATTRIBUTE[] attrs = Attribute.convert(requiredAttributes); 
            
            // создать объект с указанными атрибутами
            long hObject = module.createObject(hSession, attrs);  

            // вернуть созданный объект
            return new SessionObject(this, hObject); 
        }
    }
	// найти объекты с указанными атрибутами
	public final SessionObject[] findObjects(Attribute[] attributes)
		throws Exception			
	{
        // преобразовать атрибуты
        CK_ATTRIBUTE[] attrs = Attribute.convert(attributes); 
        
		// найти объекты с указанными атрибутами
		long[] handles = module.findObjects(hSession, attrs);

		// выделить память для объектов
		SessionObject[] objects = new SessionObject[handles.length]; 

		// для каждого найденного объекта
		for (int i = 0; i < handles.length; i++)
		{
			// создать объект по описателю
			objects[i] = new SessionObject(this, handles[i]);
		}
		return objects;
	}
	// найти объект с указанными атрибутами
	public final SessionObject findObject(Attribute[] attributes) throws Exception			
	{
        // преобразовать атрибуты
        CK_ATTRIBUTE[] attrs = Attribute.convert(attributes); 
        
		// найти объект на устройстве
		long[] handles = module.findObjects(hSession, attrs);

		// проверить корректность поиска
		if (handles.length == 0) throw new Exception(API.CKR_TEMPLATE_INCONSISTENT); 

		// проверить однозначность поиска
		if (handles.length != 1) throw new Exception(API.CKR_TEMPLATE_INCOMPLETE); 

		// вернуть найденный объект
		return new SessionObject(this, handles[0]); 
	}
	// создать объект на токене
	public final SessionObject createTokenObject(String label, 
        Attribute[] requiredAttributes, Attribute[] optionalAttributes) throws Exception			
	{
		// выделить память для атрибутов
		Attribute[] attrs = new Attribute[] {

            // указать признак нахождения на устройстве
            new Attribute(API.CKA_TOKEN, API.CK_TRUE),

            // указать имя объекта
            new Attribute(API.CKA_LABEL, label)
        }; 
		// создать объект на токене
		return createObject(
            Attribute.join(requiredAttributes, attrs), optionalAttributes
        ); 
	}
	// найти объекты с указанными атрибутами
	public final SessionObject[] findTokenObjects(
        String label, Attribute[] attributes) throws Exception			
	{
		// выделить память для атрибутов
		Attribute[] attrs = new Attribute[] {

            // указать признак нахождения на устройстве
            new Attribute(API.CKA_TOKEN, API.CK_TRUE), 

            // указать имя объекта
            new Attribute(API.CKA_LABEL, label)
        }; 
		// найти объекты на токене
		SessionObject[] objs = findObjects(Attribute.join(attributes, attrs)); 
        
        // проверить наличие объектов
        if (objs.length != 0) return objs; 
        try { 
            // проверить формат имени контейнера
            byte[] id = Array.fromHexString(label); 

            // указать для поиска имя объекта
            attrs[1] = new Attribute(API.CKA_ID, id);
        }
        // обработать возможную ошибку
        catch (IOException e) { return objs; }

        // найти объекты на токене
        return findObjects(Attribute.join(attributes, attrs)); 
	}
	// найти объект на смарт-карте с указанными атрибутами
	public final SessionObject findTokenObject(
        String label, Attribute[] attributes) throws Exception			
	{
		// выделить память для атрибутов
		Attribute[] attrs = new Attribute[] {

            // указать признак нахождения на устройстве
            new Attribute(API.CKA_TOKEN, API.CK_TRUE), 

            // указать имя объекта
            new Attribute(API.CKA_LABEL, label)
        }; 
		// найти объект на устройстве
		SessionObject[] objs = findObjects(Attribute.join(attributes, attrs)); 
        
        // проверить однозначность поиска
        if (objs.length == 1) return objs[0]; if (objs.length > 1) 
        {
            // при ошибке выбросить исключение
            throw new Exception(API.CKR_TEMPLATE_INCOMPLETE); 
        }
        try { 
            // проверить формат имени контейнера
            byte[] id = Array.fromHexString(label); 

            // указать для поиска имя объекта
            attrs[1] = new Attribute(API.CKA_ID, id);
        }
        // обработать возможную ошибку
        catch (IOException e) { return null; }

        // найти объект на токене
        objs = findObjects(Attribute.join(attributes, attrs)); 

        // проверить однозначность поиска
        if (objs.length == 1) return objs[0]; if (objs.length > 1) 
        {
            // при ошибке выбросить исключение
            throw new Exception(API.CKR_TEMPLATE_INCOMPLETE); 
        }
        return null; 
	}
	// удалить объект
	public final void destroyObject(SessionObject obj) throws Exception			
	{
		// удалить объект
		module.destroyObject(hSession, obj.handle()); 
	}
	///////////////////////////////////////////////////////////////////////////
	// Хэширование данных
	///////////////////////////////////////////////////////////////////////////

	// инициализировать алгоритм хэширования
	public void digestInit(Mechanism parameters) throws Exception
	{
		// инициализировать алгоритм хэширования
		module.digestInit(hSession, parameters.convert()); 
	}
	// захэшировать данные
	public void digestUpdate(byte[] data, int dataOff, int dataLen) throws Exception
	{
		// захэшировать данные
		module.digestUpdate(hSession, data, dataOff, dataLen); 
	}
	// захэшировать значение ключа
	public void digestKey(long hKey) throws Exception
	{
		// захэшировать значение ключа
		module.digestKey(hSession, hKey); 
	}
	// получить хэш-значение
	public int digestFinal(byte[] buf, int bufOff) throws Exception
	{
		// получить хэш-значение
		return module.digestFinal(hSession, buf, bufOff); 
	}
	///////////////////////////////////////////////////////////////////////////
	// Выработка имитовставки и подписи данных
	///////////////////////////////////////////////////////////////////////////

	// инициализировать алгоритм имитовставки или подписи данных
	public void signInit(Mechanism parameters, long hKey) throws Exception
	{
		// инициализировать алгоритм имитовставки или подписи данных
		module.signInit(hSession, parameters.convert(), hKey); 
	}	
	// обработать данные
	public void signUpdate(byte[] data, int dataOff, int dataLen) throws Exception
	{
		// обработать данные
		module.signUpdate(hSession, data, dataOff, dataLen); 
	}
	// получить имитовставку или подпись данных
	public int signFinal(byte[] buff, int bufOff) throws Exception
	{
		// получить имитовставку или подпись данных
		return module.signFinal(hSession, buff, bufOff); 
	}
	// получить имитовставку или подпись данных
	public byte[] sign(byte[] data, int dataOff, int dataLen) throws Exception
	{
		// получить имитовставку или подпись данных
		return module.sign(hSession, data, dataOff, dataLen); 
	}
	///////////////////////////////////////////////////////////////////////////
	// Проверка имитовставки и подписи данных
	///////////////////////////////////////////////////////////////////////////

	// инициализировать алгоритм имитовставки или проверки подписи
	public void verifyInit(Mechanism parameters, long hKey) throws Exception
	{
		// инициализировать алгоритм имитовставки или проверки подписи
		module.verifyInit(hSession, parameters.convert(), hKey); 
	}
	// обработать данные
	public void verifyUpdate(byte[] data, int dataOff, int dataLen) throws Exception
	{
		// обработать данные
		module.verifyUpdate(hSession, data, dataOff, dataLen); 
	}
	// проверить имитовставку или подпись данных
	public void verifyFinal(byte[] signature) throws Exception
	{
		// проверить имитовставку или подпись данных
		module.verifyFinal(hSession, signature); 
	}
	// проверить имитовставку или подпись данных
	public void verify(byte[] data, 
		int dataOff, int dataLen, byte[] signature) throws Exception
	{
		// проверить имитовставку или подпись данных
		module.verify(hSession, data, dataOff, dataLen, signature); 
	}
	///////////////////////////////////////////////////////////////////////////
	// Шифрование данных
	///////////////////////////////////////////////////////////////////////////
			
	// инициализировать алгоритм зашифрования
	public void encryptInit(Mechanism parameters, long hKey) throws Exception
	{
		// инициализировать алгоритм зашифрования
		module.encryptInit(hSession, parameters.convert(), hKey); 
	}
	// зашифровать данные
	public int encryptUpdate(byte[] data, int dataOff, int dataLen, 
        byte[] buffer, int bufferOff) throws Exception
	{
		// зашифровать данные
		return module.encryptUpdate(hSession, data, dataOff, dataLen, buffer, bufferOff); 
	}
	// завершить зашифрование данных
	public int encryptFinal(byte[] buffer, int bufferOff) throws Exception
	{
		// завершить зашифрование данных
		return module.encryptFinal(hSession, buffer, bufferOff); 
	}
	// зашифровать данные
	public byte[] encrypt(byte[] data, int dataOff, int dataLen) throws Exception
	{
		// зашифровать данные
		return module.encrypt(hSession, data, dataOff, dataLen); 
	}
	// инициализировать алгоритм расшифрования
	public void decryptInit(Mechanism parameters, long hKey) throws Exception
	{
		// инициализировать алгоритм расшифрования
		module.decryptInit(hSession, parameters.convert(), hKey); 
	}
	// расшифровать данные
	public int decryptUpdate(byte[] data, int dataOff, int dataLen, 
        byte[] buffer, int bufferOff) throws Exception
	{
		// расшифровать данные
		return module.decryptUpdate(hSession, data, dataOff, dataLen, buffer, bufferOff); 
	}
	// завершить расшифрование данных
	public int decryptFinal(byte[] buffer, int bufferOff) throws Exception
	{
		// завершить расшифрование данных
		return module.decryptFinal(hSession, buffer, bufferOff); 
	}
	// расшифровать данные
	public byte[] decrypt(byte[] data, int dataOff, int dataLen) throws Exception
	{
		// расшифровать данные
		return module.decrypt(hSession, data, dataOff, dataLen); 
	}
	///////////////////////////////////////////////////////////////////////////
	// Шифрование ключа
	///////////////////////////////////////////////////////////////////////////
			
	// зашифровать ключ
	public byte[] wrapKey(Mechanism parameters, 
		long hWrapKey, long hKey) throws Exception
	{
		// зашифровать ключ
		return module.wrapKey(hSession, parameters.convert(), hWrapKey, hKey); 
	}
	// расшифровать ключ
	public long unwrapKey(Mechanism parameters, 
		long hWrapKey, byte[] data, Attribute[] attributes) throws Exception
	{
        // преобразовать атрибуты
        CK_ATTRIBUTE[] attrs = Attribute.convert(attributes); 
        
		// расшифровать ключ
		return module.unwrapKey(hSession, parameters.convert(), hWrapKey, data, attrs); 
	}
	///////////////////////////////////////////////////////////////////////////
	// Наследование ключа
	///////////////////////////////////////////////////////////////////////////
	public long deriveKey(Mechanism parameters, 
		long hBaseKey, Attribute[] attributes) throws Exception
	{
        // преобразовать атрибуты
        CK_ATTRIBUTE[] attrs = Attribute.convert(attributes); 
        
		// выполнить наследование ключа
		return module.deriveKey(hSession, parameters.convert(), hBaseKey, attrs); 
	}
}
