using System;
using System.Security;
using System.Security.Permissions;
using System.Runtime.InteropServices;

///////////////////////////////////////////////////////////////////////////
// Определение простых типов
///////////////////////////////////////////////////////////////////////////
using CK_BBOOL          = System.Byte; 
using CK_LONG           = System.Int64; 
using CK_RV             = System.UInt64;
using CK_FLAGS          = System.UInt64; 
using CK_SLOT_ID        = System.UInt64; 
using CK_USER_TYPE      = System.UInt64; 
using CK_ATTRIBUTE_TYPE = System.UInt64; 
using CK_MECHANISM_TYPE = System.UInt64; 
using CK_SESSION_HANDLE = System.UInt64; 
using CK_OBJECT_HANDLE  = System.UInt64; 

namespace Aladdin.PKCS11
{
	///////////////////////////////////////////////////////////////////////////
	// Модуль библиотеки PKCS11 (для sizeof(long) == 8)
	///////////////////////////////////////////////////////////////////////////
	public sealed class Module64 : Module
	{
		// адреса фунций модуля и информация о модуле
		private API64.CK_FUNCTION_LIST funcList; private Info info; private bool initialized; 

		// конструктор
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
		public Module64(API.CK_GETFUNCTIONLIST getFunctionlist) 
        {
            // получить адрес списка функций
            IntPtr ptrFunctionList; Exception.Check(getFunctionlist(out ptrFunctionList)); 

            // выполнить преобразование типа
            funcList = (API64.CK_FUNCTION_LIST)Marshal.PtrToStructure(
                ptrFunctionList, typeof(API64.CK_FUNCTION_LIST)
            ); 
            // создать параметры инициализации
            API64.CK_C_INITIALIZE_ARGS initializeArgs = new API64.CK_C_INITIALIZE_ARGS(); 
            initializeArgs.Reserved = IntPtr.Zero; 

            // функции блокировки отсутствуют
            initializeArgs.CreateMutex = null; initializeArgs.DestroyMutex = null;
            initializeArgs.LockMutex   = null; initializeArgs.UnlockMutex  = null;

            // использовать системные блокировкаи
            initializeArgs.Flags = API.CKF_OS_LOCKING_OK; 

            // выделить буфер требуемого размера
            IntPtr ptr = Marshal.AllocHGlobal(Marshal.SizeOf(initializeArgs));

            // скопировать параметры
            Marshal.StructureToPtr(initializeArgs, ptr, false); 
            try {  
                // выполнить инициализацию библиотеки
                CK_RV code = funcList.C_Initialize(ptr); API64.CK_INFO ckInfo;

                // проверить инициализацию библиотеки
                if (code == API.CKR_CRYPTOKI_ALREADY_INITIALIZED) initialized = true; 

                // проверить отсутствие ошибок
                else { Exception.Check(code); initialized = false; }
                try { 
		            // получить информацию о модуле
		            Exception.Check(funcList.C_GetInfo(out ckInfo)); info = new Info(ckInfo);
                }
                // освободить выделенные ресурсы
                catch { if (!initialized) funcList.C_Finalize(IntPtr.Zero); throw; }
            }
            // освободить выделенную память
            finally { Marshal.FreeHGlobal(ptr); }
        }
        // деструктор
        protected override void OnDispose() 
        { 
            // освободить выделенные ресурсы
            if (!initialized) funcList.C_Finalize(IntPtr.Zero); base.OnDispose(); 
        } 
        // размер целого числа
        public override int LongSize { get { return 8; }} 

        // закодировать целое число
        public override byte[] EncodeLong(ulong value)
        {
            // закодировать целое число
            return BitConverter.GetBytes(value); 
        }
        // раскодировать целое число
        public override ulong DecodeLong(byte[] encoded)
        {
            // раскодировать целое число
            return BitConverter.ToUInt64(encoded, 0); 
        }
		// информация о модуле
		public override Info Info { get { return info; }} 

		///////////////////////////////////////////////////////////////////////////
		// Управление устройствами
		///////////////////////////////////////////////////////////////////////////

		// получить список считывателей
		public override ulong[] GetSlotList(bool tokenPresent)
        {
            // выполнить преобразование типа
            CK_BBOOL isPresent = (tokenPresent) ? API.CK_TRUE : API.CK_FALSE;

            // определить число считывателей
            CK_LONG ulCount = 0; Exception.Check(
	            funcList.C_GetSlotList(isPresent, null, ref ulCount)
            );
            // выделить буфер требуемого размера
            CK_SLOT_ID[] pSlotList = new CK_SLOT_ID[ulCount];

	        // получить список считывателей
	        CK_RV rv = funcList.C_GetSlotList(isPresent, pSlotList, ref ulCount); 

	        // при недосточном буфере
	        while (rv == API.CKR_BUFFER_TOO_SMALL)
	        {
		        // выделить буфер требуемого размера
		        pSlotList = new CK_SLOT_ID[ulCount];

		        // получить список считывателей
		        rv = funcList.C_GetSlotList(isPresent, pSlotList, ref ulCount); 
	        }
	        // проверить отсутствие ошибок
	        Exception.Check(rv); ulong[] slotList = new ulong[ulCount];

	        // вернуть список считывателей
            Array.Copy(pSlotList, 0, slotList, 0, ulCount); return slotList; 
        }
		// получить информацию о считывателе
		public override SlotInfo GetSlotInfo(ulong slotID)
        {
            API64.CK_SLOT_INFO info; 
	
            // получить информацию о считывателе
	        Exception.Check(funcList.C_GetSlotInfo((CK_SLOT_ID)slotID, out info)); 
	
	        // вернуть информацию о считывателе
	        return new SlotInfo(info); 
        }
		// получить информацию о смарт-карте
		public override TokenInfo GetTokenInfo(ulong slotID)
        {
            API64.CK_TOKEN_INFO info; 
	
	        // получить информацию о смарт-карте
	        Exception.Check(funcList.C_GetTokenInfo((CK_SLOT_ID)slotID, out info)); 
                
            // вернуть информацию о смарт-карте
            return new TokenInfo(info);
        }
		// инициализировать смарт-карту
		public override void InitToken(ulong slotID, string pin, string label)
        {
	        // закодировать пин-код
	        byte[] ptrPin = Encoding.EncodeString(pin); 

	        // закодировать метку
	        byte[] ptrLabel = Encoding.EncodeString(label, 32); 

            // инициализировать смарт-карту
            Exception.Check(funcList.C_InitToken(
	            (CK_SLOT_ID)slotID, ptrPin, (CK_LONG)ptrPin.Length - 1, ptrLabel
            ));         
        }
		// закрыть все сеансы со смарт-картой
		public override void CloseAllSessions(ulong slotID)
        {
            // закрыть все сеансы со смарт-картой
            funcList.C_CloseAllSessions((CK_SLOT_ID)slotID); 
        }
		///////////////////////////////////////////////////////////////////////////
		// Управление сеансами
		///////////////////////////////////////////////////////////////////////////

		// создать сеанс
		public override ulong OpenSession(ulong slotID, ulong flags)
        {
	        // указать режим открытия
	        CK_SESSION_HANDLE hSession = 0; flags |= API.CKF_SERIAL_SESSION; 

            // создать сеанс 
            Exception.Check(funcList.C_OpenSession(
	            (CK_SLOT_ID)slotID, (CK_FLAGS)flags, IntPtr.Zero, null, out hSession
            )); 
            return hSession; 
        }
		// закрыть сеанс
		public override void CloseSession(ulong hSession)
        {
            // закрыть сеанс
            funcList.C_CloseSession((CK_SESSION_HANDLE)hSession);
        }
		// получить информацию о сеансе
		public override SessionInfo GetSessionInfo(ulong hSession)
        {
            API64.CK_SESSION_INFO info; 

            // получить информацию о сеансе
	        Exception.Check(funcList.C_GetSessionInfo(
                (CK_SESSION_HANDLE)hSession, out info
            )); 
	        // вернуть информацию о сеансе
	        return new SessionInfo(info);                     
        }
		// выполнить аутентификацию смарт-карты
		public override void Login(ulong hSession, ulong userType, string pin)
        {
	        // закодировать пин-код
	        byte[] ptrPin = Encoding.EncodeString(pin); 

	        // выполнить аутентификацию смарт-карты
	        CK_RV rv = funcList.C_Login((CK_SESSION_HANDLE)hSession, 
                (CK_USER_TYPE)userType, ptrPin, (CK_LONG)ptrPin.Length - 1
	        ); 
            // проверить код ошибки
            if (rv == API.CKR_USER_ALREADY_LOGGED_IN) return; 

            // проверить отсутствие ошибок
            Exception.Check(rv); 
        }
		// отменить аутентификацию смарт-карты
		public override void Logout(ulong hSession)
        {
            // отменить аутентификацию смарт-карты
            Exception.Check(funcList.C_Logout((CK_SESSION_HANDLE)hSession)); 
        }
		// установить/изменить пин-код для CKU_USER от имени администратора
		public override void InitPIN(ulong hSession, string pin)
        {
	        // закодировать пин-код
	        byte[] ptrPin = Encoding.EncodeString(pin); 

            // установить первоначальный пин-код
            Exception.Check(funcList.C_InitPIN(
	            (CK_SESSION_HANDLE)hSession, 
                ptrPin, (CK_LONG)ptrPin.Length - 1
            )); 
        }
		// изменить пин-код текущего пользователя
		public override void SetPIN(ulong hSession, string pinOld, string pinNew)
        {
	        // закодировать пин-код
	        byte[] ptrPinOld = Encoding.EncodeString(pinOld);  
	        byte[] ptrPinNew = Encoding.EncodeString(pinNew);  

            // изменить пин-код
            Exception.Check(funcList.C_SetPIN((CK_SESSION_HANDLE)hSession, 
	            ptrPinOld, (CK_LONG)ptrPinOld.Length - 1, 
                ptrPinNew, (CK_LONG)ptrPinNew.Length - 1
            )); 
        }
		///////////////////////////////////////////////////////////////////////////
		// Управление алгоритмами
		///////////////////////////////////////////////////////////////////////////

		// получить список алгоритмов
		public override ulong[] GetAlgorithmList(ulong slotID)
        {
            // определить число алгоритмов
            CK_LONG ulCount = 0; Exception.Check(
	            funcList.C_GetMechanismList((CK_SLOT_ID)slotID, null, ref ulCount)
            );
            // выделить буфер требуемого размера
            CK_MECHANISM_TYPE[] pMechanismList = new CK_MECHANISM_TYPE[ulCount];

	        // получить список алгоритмов
	        CK_RV rv = funcList.C_GetMechanismList(
                (CK_SLOT_ID)slotID, pMechanismList, ref ulCount
            ); 
	        // при недосточном буфере
	        while (rv == API.CKR_BUFFER_TOO_SMALL)
	        {
		        // выделить буфер требуемого размера
		        pMechanismList = new CK_MECHANISM_TYPE[ulCount];

		        // получить список алгоритмов
		        rv = funcList.C_GetMechanismList(
                    (CK_SLOT_ID)slotID, pMechanismList, ref ulCount
                ); 
	        }
            // выделить буфер требуемого размера
	        Exception.Check(rv); ulong[] mechanismList = new ulong[ulCount];

	        // скопировать список алгоритмов
            Array.Copy(pMechanismList, 0, mechanismList, 0, ulCount); return mechanismList; 
        }
		// получить информацию об алгоритме
		public override MechanismInfo GetAlgorithmInfo(ulong slotID, ulong type)
        {
            API64.CK_MECHANISM_INFO info; 
	
            // получить информацию об алгоритме
            Exception.Check(funcList.C_GetMechanismInfo(
                (CK_SLOT_ID)slotID, (CK_MECHANISM_TYPE)type, out info)
            ); 
           	// вернуть информацию об алгоритме
            return new MechanismInfo(info); 
        }
		///////////////////////////////////////////////////////////////////////////
		// Генерация случайных данных
		///////////////////////////////////////////////////////////////////////////

		// установить стартовое значение для генератора 
		public override void SeedRandom(ulong hSession, 
            byte[] buffer, int offset, int length)
        {
            // скопировать данные
            byte[] buf = new byte[length]; Array.Copy(buffer, offset, buf, 0, length); 

            // установить стартовое значение для генератора 
            Exception.Check(funcList.C_SeedRandom(
                (CK_SESSION_HANDLE)hSession, buf, (CK_LONG)length
            )); 
        }
		// сгенерировать случайные данные
		public override void GenerateRandom(ulong hSession, 
            byte[] buffer, int offset, int length)
        {
	        // выделить буфер требуемого размера
	        byte[] buf = new byte[length]; 

            // сгенерировать случайные данные
            Exception.Check(funcList.C_GenerateRandom(
                (CK_SESSION_HANDLE)hSession, buf, (CK_LONG)length
            ));
            // скопировать данные
            Array.Copy(buf, 0, buffer, offset, length); 
        }
        ///////////////////////////////////////////////////////////////////////////
        // Преобразование типа атрибутов 
        ///////////////////////////////////////////////////////////////////////////
        private sealed class AllocatedAttributes : Disposable
        {
            // адрес выделенной памяти и описание атрибутов
            private IntPtr ptr; private API64.CK_ATTRIBUTE[] ckAttributes; 

            // конструктор
            [SecuritySafeCritical]
            [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
            public AllocatedAttributes(Attribute[] attributes)
            {
	            // проверить наличие атрибутов
	            if (attributes == null) attributes = new Attribute[0]; 

                // выделить описание атрибутов
                ckAttributes = new API64.CK_ATTRIBUTE[attributes.Length]; 

                // указать фиксированный размер
                int cbHeader = attributes.Length * Marshal.SizeOf(typeof(API64.CK_ATTRIBUTE)); 

	            // для каждого атрибута
	            int cbTotal = 0; foreach (Attribute attribute in attributes)
	            {
                    // указать фиксированный размер
                    cbTotal += Marshal.SizeOf(typeof(API64.CK_ATTRIBUTE)); 

		            // увеличить требуемый размер
		            if (attribute.Value != null) cbTotal += attribute.Value.Length; 
	            }
	            // выделить память для атрибутов
	            ptr = Marshal.AllocHGlobal(cbTotal); IntPtr ptrFix = ptr; 
                
                // указать адрес для значения атрибутов
                IntPtr ptrVar = new IntPtr(ptr.ToInt64() + cbHeader);
                
                // для всех атрибутов
                for (int i = 0; i < attributes.Length; i++)
                {
		            // установить тип атрибута
		            ckAttributes[i].type = (CK_ATTRIBUTE_TYPE)attributes[i].Type; 

		            // установить отсутствие значения атрибута
		            ckAttributes[i].pValue = IntPtr.Zero; ckAttributes[i].ulValueLen = 0; 
                
		            // проверить наличие значения
		            if (attributes[i].Value != null) { ckAttributes[i].pValue = ptrVar;

		                // установить размер атрибута
		                ckAttributes[i].ulValueLen = attributes[i].Value.Length;

		                // скопировать значение атрибута
		                Marshal.Copy(attributes[i].Value, 0, ptrVar, attributes[i].Value.Length); 

                        // увеличить значение текущего адреса
                        ptrVar = new IntPtr(ptrVar.ToInt64() + attributes[i].Value.Length); 
                    }
                    // скопировать заголовок атрибута
                    Marshal.StructureToPtr(ckAttributes[i], ptrFix, false); 

                    // увеличить значение текущего адреса
                    ptrFix = new IntPtr(ptrFix.ToInt64() + Marshal.SizeOf(typeof(API64.CK_ATTRIBUTE))); 
                }
            }
            // конструктор
            [SecuritySafeCritical]
            [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
            public AllocatedAttributes(API64.CK_ATTRIBUTE[] ckAttributes)
            {
	            // проверить наличие атрибутов
	            if (ckAttributes == null) ckAttributes = new API64.CK_ATTRIBUTE[0]; this.ckAttributes = ckAttributes; 

                // указать фиксированный размер
                int cbHeader = ckAttributes.Length * Marshal.SizeOf(typeof(API32.CK_ATTRIBUTE)); 

	            // для каждого атрибута
	            int cbTotal = 0; foreach (API64.CK_ATTRIBUTE ckAttribute in ckAttributes)
	            {
                    // указать фиксированный размер
                    cbTotal += Marshal.SizeOf(typeof(API64.CK_ATTRIBUTE)); 

		            // увеличить требуемый размер
		            if (ckAttribute.ulValueLen != 0) cbTotal += (int)ckAttribute.ulValueLen; 
	            }
	            // выделить память для атрибутов
	            ptr = Marshal.AllocHGlobal(cbTotal); IntPtr ptrFix = ptr; 

                // указать адрес для значения атрибутов
                IntPtr ptrVar = new IntPtr(ptr.ToInt64() + cbHeader);
                
                // для всех атрибутов
                for (int i = 0; i < ckAttributes.Length; i++)
                {
		            // проверить наличие значения
		            if (ckAttributes[i].ulValueLen == 0) ckAttributes[i].pValue = IntPtr.Zero;
                    else { 
                        // указать адрес для значения 
                        ckAttributes[i].pValue = ptrVar; 

                        // увеличить значение текущего адреса
                        ptrVar = new IntPtr(ptrVar.ToInt64() + ckAttributes[i].ulValueLen); 
                    }
                    // скопировать заголовок атрибута
                    Marshal.StructureToPtr(ckAttributes[i], ptrFix, false); 

                    // увеличить значение текущего адреса
                    ptrFix = new IntPtr(ptrFix.ToInt64() + Marshal.SizeOf(typeof(API64.CK_ATTRIBUTE))); 
                }
            }
            // освободить выделенную память
            [SecuritySafeCritical]
            [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
            protected override void OnDispose() { Marshal.FreeHGlobal(ptr); base.OnDispose(); }

            // выполнить синхронизацию
            [SecuritySafeCritical]
            [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
            public API64.CK_ATTRIBUTE[] Synchronize()
            {
                // для всех атрибутов
                IntPtr ptrFix = ptr;  for (int i = 0; i < ckAttributes.Length; i++)
                {
                    // извлечть описание атрибута
                    ckAttributes[i] = (API64.CK_ATTRIBUTE)Marshal.PtrToStructure(ptrFix, typeof(API64.CK_ATTRIBUTE)); 

                    // увеличить значение текущего адреса
                    ptrFix = new IntPtr(ptrFix.ToInt64() + Marshal.SizeOf(typeof(API64.CK_ATTRIBUTE))); 
                }
                return ckAttributes; 
            }
            // преобразованные атрибуты
            public API64.CK_ATTRIBUTE[] Values { get { return ckAttributes; }} 

            // адрес атрибутов
            public IntPtr Pointer { get { return ptr; }}
            // число атрибутов
            public CK_LONG Count { get { return ckAttributes.Length; }}
        }
        ///////////////////////////////////////////////////////////////////////////
        // Поиск объектов
        ///////////////////////////////////////////////////////////////////////////
        private sealed class ObjectFinder : Disposable
        {
		    // адреса фунций модуля 
            private API64.CK_FINDOBJECTS      findObjects; 
            private API64.CK_FINDOBJECTSFINAL findObjectsFinal; 

            // описатель сеанса и выделенные атрибуты
            private CK_SESSION_HANDLE hSession; private AllocatedAttributes allocated; 

            // конструктор
            public ObjectFinder(ref API64.CK_FUNCTION_LIST funcList, 
                CK_SESSION_HANDLE hSession, Attribute[] attributes)
            {
                // выделить память для атрибутов
                allocated = new AllocatedAttributes(attributes); 

                // инициализировать поиск объектов
                Exception.Check(funcList.C_FindObjectsInit(hSession, allocated.Pointer, allocated.Count));

                // сохранить адреса фунций модуля 
                findObjectsFinal = funcList.C_FindObjectsFinal; 

                // сохранить адреса фунций модуля 
                findObjects = funcList.C_FindObjects; this.hSession = hSession; 
            }
            // деструктор
            protected override void OnDispose() { findObjectsFinal(hSession); 
                
                // освободить выделенные ресурсы
                allocated.Dispose(); base.OnDispose(); 
            }
            // найти объекты
		    public CK_OBJECT_HANDLE[] Find()
            {
		        // выделить память для списка идентификаторов
		        CK_OBJECT_HANDLE[] objects = new CK_OBJECT_HANDLE[0]; CK_LONG ulObjectCount; 
                do {
		            // выделить память для идентификаторов
                    CK_OBJECT_HANDLE[] objs = new CK_OBJECT_HANDLE[1024]; 

		            // найти идентификаторы объектов с указанными атрибутами
		            Exception.Check(findObjects(hSession, objs, 1024, out ulObjectCount));

			        // увеличить размер списка идентификаторов
			        Array.Resize(ref objects, objects.Length + (int)ulObjectCount); 

                    // скопировать идентификаторы
                    Array.Copy(objs, 0, objects, 
                        objects.Length - ulObjectCount, ulObjectCount
                    ); 
                }
		        // продолжать до окончания поиска
		        while (ulObjectCount == 1024); return objects; 
            }
        }
		///////////////////////////////////////////////////////////////////////////
		// Управление объектами
		///////////////////////////////////////////////////////////////////////////

		// создать объект
		public override ulong CreateObject(ulong hSession, Attribute[] attributes)
        {
	        CK_OBJECT_HANDLE hObject = 0; 

            // выполнить преобразование атрибутов
            using (AllocatedAttributes allocated = new AllocatedAttributes(attributes))
            {
	            // создать объект
	            Exception.Check(funcList.C_CreateObject(
	                (CK_SESSION_HANDLE)hSession, 
                    allocated.Pointer, allocated.Count, out hObject
	            )); 
            }
            return hObject; 
        }
		// скопировать объект
		public override ulong CopyObject(ulong hSession, ulong hObject, Attribute[] attributes)
        {
	        CK_OBJECT_HANDLE hCopyObject = 0; 

            // выполнить преобразование атрибутов
            using (AllocatedAttributes allocated = new AllocatedAttributes(attributes))
            {
                // скопировать объект
	            Exception.Check(funcList.C_CreateObject(
		            (CK_SESSION_HANDLE)hSession, 
                    allocated.Pointer, allocated.Count, out hCopyObject
	            )); 
            }
            return hCopyObject; 
        }
		// закрыть объект
		public override void DestroyObject(ulong hSession, ulong hObject)
        {
           	// удалить/закрыть объект
            funcList.C_DestroyObject((CK_SESSION_HANDLE)hSession, (CK_OBJECT_HANDLE)hObject); 
        }
		// найти объекты
		public override ulong[] FindObjects(ulong hSession, Attribute[] attributes)
        {
            // создать объект поиска
            using (ObjectFinder finder = new ObjectFinder(
                ref funcList, (CK_SESSION_HANDLE)hSession, attributes))
            { 
                // найти объекты
                CK_OBJECT_HANDLE[] objs = finder.Find(); ulong[] objects = new ulong[objs.Length];

                // скопировать объекты
                Array.Copy(objs, 0, objects, 0, objs.Length); return objects; 
            }
        }
		// получить значение атрибутов
		public override Attribute[] GetAttributes(
            ulong hSession, ulong hObject, Attribute[] attributes)
        {
		    // скопировать атрибуты
		    attributes = (Attribute[])attributes.Clone();
            try { 
                // выделить буфер требуемого размера
                API64.CK_ATTRIBUTE[] attrs = new API64.CK_ATTRIBUTE[attributes.Length]; 

                // для всех атрибутов
                for (int i = 0; i < attributes.Length; i++)
                {
                    // установить тип атрибута
                    attrs[i].type = (CK_ATTRIBUTE_TYPE)attributes[i].Type; 
			
		            // установить отсутствие значения атрибута
		            attrs[i].pValue = IntPtr.Zero; attrs[i].ulValueLen = 0; 
                }
                // выполнить преобразование атрибутов
                using (AllocatedAttributes converted = new AllocatedAttributes(attrs))
                {
	                // определить размер атрибутов
	                Exception.Check(funcList.C_GetAttributeValue(
                        (CK_SESSION_HANDLE)hSession, (CK_OBJECT_HANDLE)hObject, 
                        converted.Pointer, converted.Count
                    )); 
                    // выполнить преобразование атрибутов
                    using (AllocatedAttributes allocated = new AllocatedAttributes(converted.Synchronize()))
                    {
		                // получить значение атрибутов
		                Exception.Check(funcList.C_GetAttributeValue(
                            (CK_SESSION_HANDLE)hSession, (CK_OBJECT_HANDLE)hObject, 
                            allocated.Pointer, allocated.Count
                        )); 
                        // для всех атрибутов
                        for (int i = 0; i < attributes.Length; i++)
                        {
		                    // сохранить значение атрибута
		                    attributes[i] = new Attribute(allocated.Values[i]); 
                        }
                    }
                }
                return attributes; 
            }
            // выделить память для атрибута
            catch (Exception) { API64.CK_ATTRIBUTE[] attrs = new API64.CK_ATTRIBUTE[1]; 

	            // для каждого атрибута
	            for (int i = 0; i < attributes.Length; i++)
	            {
                    // установить тип атрибута
                    attrs[0].type = (CK_ATTRIBUTE_TYPE)attributes[i].Type; 
			
		            // установить отсутствие значения атрибута
		            attrs[0].pValue = IntPtr.Zero; attrs[0].ulValueLen = 0; 

                    // выполнить преобразование атрибутов
                    using (AllocatedAttributes converted = new AllocatedAttributes(attrs))
                    {
		                // определить размер атрибутов
		                CK_RV rv = funcList.C_GetAttributeValue(
                            (CK_SESSION_HANDLE)hSession, (CK_OBJECT_HANDLE)hObject, converted.Pointer, 1
                        ); 
                        // при наличии ошибки
                        if (rv != 0) { if (attributes[i].Value == null) Exception.Check(rv); continue; }

                        // выполнить преобразование атрибутов
                        using (AllocatedAttributes allocated = new AllocatedAttributes(converted.Synchronize()))
                        {
		                    // получить значение атрибутов
		                    rv = funcList.C_GetAttributeValue(
                                (CK_SESSION_HANDLE)hSession, (CK_OBJECT_HANDLE)hObject, allocated.Pointer, 1
                            ); 
                            // при наличии ошибки
                            if (rv != 0) { if (attributes[i].Value == null) Exception.Check(rv); continue; } 

		                    // создать атрибут по значению
		                    attributes[i] = new Attribute(allocated.Values[0]); 
                        }
                    }
                }
                return attributes; 
            }
	    }
		// установить значение атрибута
		public override void SetAttributes(ulong hSession, ulong hObject, Attribute[] attributes)
        {
            // выполнить преобразование атрибутов
            using (AllocatedAttributes allocated = new AllocatedAttributes(attributes))
            {
                // установить значения атрибутов
	            Exception.Check(funcList.C_SetAttributeValue(
		            (CK_SESSION_HANDLE)hSession, (CK_OBJECT_HANDLE)hObject, 
                    allocated.Pointer, allocated.Count
	            )); 
            }
        }
		// определить размер объекта на смарт-карте
		public override int GetObjectSize(ulong hSession, ulong hObject)
        {
            // определить размер объекта на смарт-карте
            CK_LONG ulSize; Exception.Check(funcList.C_GetObjectSize(
                (CK_SESSION_HANDLE)hSession, (CK_OBJECT_HANDLE)hObject, out ulSize
            )); 
            return (int)ulSize;  
        }
		///////////////////////////////////////////////////////////////////////////
		// Управление ключами
		///////////////////////////////////////////////////////////////////////////

		// создать симметричный ключ
		public override ulong GenerateKey(ulong hSession, Mechanism parameters, Attribute[] attributes)
        {
	        CK_OBJECT_HANDLE hKey = 0;

            // закодировать параметры алгоритма
            using (MechanismBuffer mechanismParameters = parameters.Encode(this))
            { 
	            // указать параметры алгоритма
	            API64.CK_MECHANISM mechanism = new API64.CK_MECHANISM(
                    (CK_MECHANISM_TYPE)parameters.AlgID, 
                    mechanismParameters.Ptr, (CK_LONG)mechanismParameters.Size
                ); 
                // выполнить преобразование атрибутов
                using (AllocatedAttributes allocated = new AllocatedAttributes(attributes))
                {
	                // создать симметричный ключ
	                Exception.Check(funcList.C_GenerateKey((CK_SESSION_HANDLE)hSession, 
                        ref mechanism, allocated.Pointer, allocated.Count, out hKey
	                )); 
                }
            }
	        return hKey; 
        }
		// создать пару ассиметричных ключей
		public override ulong[] GenerateKeyPair(ulong hSession, Mechanism parameters, 
			Attribute[] publicAttributes, Attribute[] privateAttributes)
        {
	        CK_OBJECT_HANDLE hPublicKey = 0; CK_OBJECT_HANDLE hPrivateKey = 0;

            // закодировать параметры алгоритма
            using (MechanismBuffer mechanismParameters = parameters.Encode(this))
            { 
	            // указать параметры алгоритма
	            API64.CK_MECHANISM mechanism = new API64.CK_MECHANISM(
                    (CK_MECHANISM_TYPE)parameters.AlgID, 
                    mechanismParameters.Ptr, (CK_LONG)mechanismParameters.Size
                ); 
                // выполнить преобразование атрибутов
                using (AllocatedAttributes allocatedPublic = new AllocatedAttributes(publicAttributes))
                {
                    // выполнить преобразование атрибутов
                    using (AllocatedAttributes allocatedPrivate = new AllocatedAttributes(privateAttributes))
                    {
	                    // создать пару ассиметричных ключей
	                    Exception.Check(funcList.C_GenerateKeyPair((CK_SESSION_HANDLE)hSession, 
                            ref mechanism, allocatedPublic.Pointer, allocatedPublic.Count, 
		                    allocatedPrivate.Pointer, allocatedPrivate.Count, out hPublicKey, out hPrivateKey
	                    )); 
                    }
                }
            }
            // вернуть список ключей
            return new ulong[] { hPublicKey, hPrivateKey }; 
        }
		///////////////////////////////////////////////////////////////////////////
		// Хэширование данных
		///////////////////////////////////////////////////////////////////////////

		// инициализировать алгоритм хэширования
		public override void DigestInit(ulong hSession, Mechanism parameters)
        {
            // закодировать параметры алгоритма
            using (MechanismBuffer mechanismParameters = parameters.Encode(this))
            { 
	            // указать параметры алгоритма
	            API64.CK_MECHANISM mechanism = new API64.CK_MECHANISM(
                    (CK_MECHANISM_TYPE)parameters.AlgID, 
                    mechanismParameters.Ptr, (CK_LONG)mechanismParameters.Size
                ); 
	            // инициализировать алгоритм хэширования
	            Exception.Check(funcList.C_DigestInit((CK_SESSION_HANDLE)hSession, ref mechanism)); 	
            }
        }
		// захэшировать данные
		public override void DigestUpdate(ulong hSession, 
			byte[] data, int dataOff, int dataLen)
        {
            // скопировать входные данные
            byte[] input = new byte[dataLen]; Array.Copy(data, dataOff, input, 0, dataLen); 

	        // захэшировать данные
	        Exception.Check(funcList.C_DigestUpdate(
                (CK_SESSION_HANDLE)hSession, input, (CK_LONG)dataLen
            )); 
        }
		// захэшировать значение ключа
		public override void DigestKey(ulong hSession, ulong hKey)
        {
	        // захэшировать значение ключа
	        Exception.Check(funcList.C_DigestKey(
                (CK_SESSION_HANDLE)hSession, (CK_OBJECT_HANDLE)hKey
            )); 
        }
		// получить хэш-значение
		public override int DigestFinal(ulong hSession, byte[] buf, int bufOff)
        {
	        // определить размер хэш-значения
	        CK_LONG cbDigest = 0; Exception.Check(funcList.C_DigestFinal(
                (CK_SESSION_HANDLE)hSession, null, ref cbDigest
            )); 
	        // вернуть размер хэш-значения
	        if (buf == null) return (int)cbDigest; if (buf.Length < bufOff + cbDigest)
	        {
		        // при ошибке выбросить исключение
		        throw new Exception(API.CKR_BUFFER_TOO_SMALL); 
	        }
	        // выделить память для хэш-значения
	        byte[] digest = new byte[cbDigest]; 

	        // получить хэш-значение
	        Exception.Check(funcList.C_DigestFinal(
                (CK_SESSION_HANDLE)hSession, digest, ref cbDigest
            )); 
	        // вернуть хэш-значение
	        Array.Copy(digest, 0, buf, bufOff, cbDigest); return (int)cbDigest; 
        }
		///////////////////////////////////////////////////////////////////////////
		// Выработка имитовставки и подписи данных
		///////////////////////////////////////////////////////////////////////////

		// инициализировать алгоритм имитовставки или подписи данных
		public override void SignInit(ulong hSession, Mechanism parameters, ulong hKey)
        {
            // закодировать параметры алгоритма
            using (MechanismBuffer mechanismParameters = parameters.Encode(this))
            { 
	            // указать параметры алгоритма
	            API64.CK_MECHANISM mechanism = new API64.CK_MECHANISM(
                    (CK_MECHANISM_TYPE)parameters.AlgID, 
                    mechanismParameters.Ptr, (CK_LONG)mechanismParameters.Size
                ); 
	            // инициализировать алгоритм имитовставки или подписи данных
	            Exception.Check(funcList.C_SignInit(
                    (CK_SESSION_HANDLE)hSession, ref mechanism, (CK_OBJECT_HANDLE)hKey
                )); 	
            }
        }
		// обработать данные
		public override void SignUpdate(ulong hSession, 
			byte[] data, int dataOff, int dataLen)
        {
            // скопировать входные данные
            byte[] input = new byte[dataLen]; Array.Copy(data, dataOff, input, 0, dataLen); 

	        // обработать данные
	        Exception.Check(funcList.C_SignUpdate(
                (CK_SESSION_HANDLE)hSession, input, (CK_LONG)dataLen
            )); 
        }
		// получить имитовставку или подпись данных
		public override int SignFinal(ulong hSession, byte[] buf, int bufOff)
        {
	        // определить размер имитовставки или подписи данных
	        CK_LONG cbSign = 0; Exception.Check(funcList.C_SignFinal(
                (CK_SESSION_HANDLE)hSession, null, ref cbSign
            )); 
	        // вернуть размер имитовставки или подписи данных
	        if (buf == null) return (int)cbSign; if (buf.Length < bufOff + cbSign)
	        {
		        // при ошибке выбросить исключение
		        throw new Exception(API.CKR_BUFFER_TOO_SMALL); 
	        }
	        // выделить память для имитовставки или подписи данных
	        byte[] signature = new byte[cbSign]; 

	        // получить имитовставку или подпись данных
	        Exception.Check(funcList.C_SignFinal(
                (CK_SESSION_HANDLE)hSession, signature, ref cbSign
            )); 
	        // вернуть имитовставку или подпись данных
	        Array.Copy(signature, 0, buf, bufOff, cbSign); return (int)cbSign;         
        }
		// получить имитовставку или подпись данных
		public override byte[] Sign(ulong hSession, byte[] data, int dataOff, int dataLen)
        {
	        // скопировать исходные данные
            byte[] input = new byte[dataLen]; Array.Copy(data, dataOff, input, 0, dataLen); 

	        // определить размер имитовставки или подписи данных
	        CK_LONG cbSign = 0; Exception.Check(funcList.C_Sign(
                (CK_SESSION_HANDLE)hSession, 
                input, (CK_LONG)dataLen, null, ref cbSign
            )); 
	        // выделить память для имитовставки или подписи данных
	        byte[] signature = new byte[cbSign]; 

	        // получить имитовставку или подпись данных
	        Exception.Check(funcList.C_Sign(
                (CK_SESSION_HANDLE)hSession, 
                input, (CK_LONG)dataLen, signature, ref cbSign
            )); 
	        // изменить размер буфера
	        Array.Resize(ref signature, (int)cbSign); return signature;        
        }
		///////////////////////////////////////////////////////////////////////////
		// Проверка имитовставки и подписи данных
		///////////////////////////////////////////////////////////////////////////

		// инициализировать алгоритм имитовставки или проверки подписи
		public override void VerifyInit(ulong hSession, Mechanism parameters, ulong hKey)
        {
            // закодировать параметры алгоритма
            using (MechanismBuffer mechanismParameters = parameters.Encode(this))
            { 
	            // указать параметры алгоритма
	            API64.CK_MECHANISM mechanism = new API64.CK_MECHANISM(
                    (CK_MECHANISM_TYPE)parameters.AlgID, 
                    mechanismParameters.Ptr, (CK_LONG)mechanismParameters.Size
                ); 
	            // инициализировать алгоритм имитовставки или проверки подписи
	            Exception.Check(funcList.C_VerifyInit(
                    (CK_SESSION_HANDLE)hSession, ref mechanism, (CK_OBJECT_HANDLE)hKey
                )); 	
            }
        }
		// обработать данные
		public override void VerifyUpdate(ulong hSession, 
			byte[] data, int dataOff, int dataLen)
        {
            // скопировать входные данные
            byte[] input = new byte[dataLen]; Array.Copy(data, dataOff, input, 0, dataLen); 

	        // обработать данные
	        Exception.Check(funcList.C_VerifyUpdate(
                (CK_SESSION_HANDLE)hSession, input, (CK_LONG)dataLen
            )); 
        }
		// проверить имитовставку или подпись данных
		public override void VerifyFinal(ulong hSession, byte[] signature)
        {
	        // проверить имитовставку или подпись данных
	        Exception.Check(funcList.C_VerifyFinal(
                (CK_SESSION_HANDLE)hSession, 
                signature, (CK_LONG)signature.Length
            )); 
        }
		// проверить имитовставку или подпись данных
		public override void Verify(ulong hSession, 
            byte[] data, int dataOff, int dataLen, byte[] signature)
        {
	        // скопировать исходные данные
            byte[] input = new byte[dataLen]; Array.Copy(data, dataOff, input, 0, dataLen); 

	        // проверить имитовставку или подпись данных
	        Exception.Check(funcList.C_Verify(
		        (CK_SESSION_HANDLE)hSession, input, (CK_LONG)dataLen, 
                signature, (CK_LONG)signature.Length
	        )); 
        }
		///////////////////////////////////////////////////////////////////////////
		// Шифрование данных
		///////////////////////////////////////////////////////////////////////////

		// инициализировать алгоритм зашифрования
		public override void EncryptInit(ulong hSession, Mechanism parameters, ulong hKey)
        {
            // закодировать параметры алгоритма
            using (MechanismBuffer mechanismParameters = parameters.Encode(this))
            { 
	            // указать параметры алгоритма
	            API64.CK_MECHANISM mechanism = new API64.CK_MECHANISM(
                    (CK_MECHANISM_TYPE)parameters.AlgID, 
                    mechanismParameters.Ptr, (CK_LONG)mechanismParameters.Size
                ); 
	            // инициализировать алгоритм зашифрования
	            Exception.Check(funcList.C_EncryptInit(
                    (CK_SESSION_HANDLE)hSession, ref mechanism, (CK_OBJECT_HANDLE)hKey
                )); 	
            }
        }
		// зашифровать данные
		public override int EncryptUpdate(ulong hSession, byte[] data, 
			int dataOff, int dataLen, byte[] buffer, int bufferOff)
        {
            // скопировать входные данные
            byte[] input = new byte[dataLen]; Array.Copy(data, dataOff, input, 0, dataLen); 

            // выделить буфер требуемого размера
            CK_LONG cb = (CK_LONG)dataLen + 32; byte[] output = new byte[cb]; 

	        // зашифровать данные
	        Exception.Check(funcList.C_EncryptUpdate(
                (CK_SESSION_HANDLE)hSession, input, 
                (CK_LONG)dataLen, output, ref cb
            )); 
	        // скопировать результат
	        Array.Copy(output, 0, buffer, bufferOff, cb); return (int)cb;
        }
		// завершить зашифрование данных
		public override int EncryptFinal(ulong hSession, byte[] buffer, int bufferOff)
        {
            // выделить буфер требуемого размера
            CK_LONG cb = 32; byte[] output = new byte[cb]; 

	        // завершить зашифрование данных
	        Exception.Check(funcList.C_EncryptFinal(
                (CK_SESSION_HANDLE)hSession, output, ref cb
            )); 
	        // скопировать результат
	        Array.Copy(output, 0, buffer, bufferOff, cb); return (int)cb; 
        }
		// зашифровать данные
		public override byte[] Encrypt(ulong hSession, byte[] data, int dataOff, int dataLen)
        {
            // скопировать входные данные
            byte[] input = new byte[dataLen]; Array.Copy(data, dataOff, input, 0, dataLen); 

	        // определить размер зашифрованных данных
	        CK_LONG cb = 0; Exception.Check(funcList.C_Encrypt(
                (CK_SESSION_HANDLE)hSession, input, 
                (CK_LONG)dataLen, null, ref cb
            )); 
	        // выделить память для зашифрованных данных
	        byte[] output = new byte[cb]; 

	        // зашифровать данные
	        Exception.Check(funcList.C_Encrypt(
                (CK_SESSION_HANDLE)hSession, input, 
                (CK_LONG)dataLen, output, ref cb
            )); 
	        // изменить размер буфера
	        Array.Resize(ref output, (int)cb); return output;
        }
		// инициализировать алгоритм расшифрования
		public override void DecryptInit(ulong hSession, Mechanism parameters, ulong hKey)
        {
            // закодировать параметры алгоритма
            using (MechanismBuffer mechanismParameters = parameters.Encode(this))
            { 
	            // указать параметры алгоритма
	            API64.CK_MECHANISM mechanism = new API64.CK_MECHANISM(
                    (CK_MECHANISM_TYPE)parameters.AlgID, 
                    mechanismParameters.Ptr, (CK_LONG)mechanismParameters.Size
                ); 
	            // инициализировать алгоритм расшифрования
	            Exception.Check(funcList.C_DecryptInit(
                    (CK_SESSION_HANDLE)hSession, ref mechanism, (CK_OBJECT_HANDLE)hKey
                )); 	
            }
        }
		// расшифровать данные
		public override int DecryptUpdate(ulong hSession, 
            byte[] data, int dataOff, int dataLen, byte[] buffer, int bufferOff)
        {
            // скопировать входные данные
            byte[] input = new byte[dataLen]; Array.Copy(data, dataOff, input, 0, dataLen); 

            // выделить буфер требуемого размера
            CK_LONG cb = (CK_LONG)dataLen + 32; byte[] output = new byte[cb]; 

	        // зашифровать данные
	        Exception.Check(funcList.C_DecryptUpdate(
                (CK_SESSION_HANDLE)hSession, input, 
                (CK_LONG)dataLen, output, ref cb
            )); 
	        // скопировать результат
	        Array.Copy(output, 0, buffer, bufferOff, cb); return (int)cb;
        }
		// завершить расшифрование данных
		public override int DecryptFinal(ulong hSession, byte[] buffer, int bufferOff)
        {
            // выделить буфер требуемого размера
            CK_LONG cb = 32; byte[] output = new byte[cb]; 

	        // завершить зашифрование данных
	        Exception.Check(funcList.C_DecryptFinal(
                (CK_SESSION_HANDLE)hSession, output, ref cb
            )); 
	        // скопировать результат
	        Array.Copy(output, 0, buffer, bufferOff, cb); return (int)cb; 
        }
		// расшифровать данные
		public override byte[] Decrypt(ulong hSession, byte[] data, int dataOff, int dataLen)
        {
            // скопировать входные данные
            byte[] input = new byte[dataLen]; Array.Copy(data, dataOff, input, 0, dataLen); 

	        // определить размер зашифрованных данных
	        CK_LONG cb = 0; Exception.Check(funcList.C_Decrypt(
                (CK_SESSION_HANDLE)hSession, input, 
                (CK_LONG)dataLen, null, ref cb
            )); 
	        // выделить память для зашифрованных данных
	        byte[] output = new byte[cb]; 

	        // зашифровать данные
	        Exception.Check(funcList.C_Decrypt(
                (CK_SESSION_HANDLE)hSession, input, 
                (CK_LONG)dataLen, output, ref cb
            )); 
	        // изменить размер буфера
	        Array.Resize(ref output, (int)cb); return output;
        }
		///////////////////////////////////////////////////////////////////////////
		// Шифрование ключа
		///////////////////////////////////////////////////////////////////////////

		// зашифровать ключ
		public override byte[] WrapKey(ulong hSession, 
            Mechanism parameters, ulong hWrapKey, ulong hKey)
        {
            // закодировать параметры алгоритма
            using (MechanismBuffer mechanismParameters = parameters.Encode(this))
            { 
	            // указать параметры алгоритма
	            API64.CK_MECHANISM mechanism = new API64.CK_MECHANISM(
                    (CK_MECHANISM_TYPE)parameters.AlgID, 
                    mechanismParameters.Ptr, (CK_LONG)mechanismParameters.Size
                ); 
	            // определить размер зашифрованного ключа
	            CK_LONG cb = 0; Exception.Check(funcList.C_WrapKey(
		            (CK_SESSION_HANDLE)hSession, ref mechanism, 
                    (CK_OBJECT_HANDLE)hWrapKey, (CK_OBJECT_HANDLE)hKey, null, ref cb
	            )); 
	            // выделить память для зашифрованного ключа
	            byte[] output = new byte[cb]; 

	            // зашифровать ключ
	            Exception.Check(funcList.C_WrapKey(
		            (CK_SESSION_HANDLE)hSession, ref mechanism, 
                    (CK_OBJECT_HANDLE)hWrapKey, (CK_OBJECT_HANDLE)hKey, output, ref cb
	            )); 
	            // изменить размер буфера
	            Array.Resize(ref output, (int)cb); return output; 
            }
        }
		// расшифровать ключ
		public override ulong UnwrapKey(ulong hSession, 
			Mechanism parameters, ulong hWrapKey, byte[] data, Attribute[] attributes)
        {
	        CK_OBJECT_HANDLE hKey = 0;

            // закодировать параметры алгоритма
            using (MechanismBuffer mechanismParameters = parameters.Encode(this))
            { 
	            // указать параметры алгоритма
	            API64.CK_MECHANISM mechanism = new API64.CK_MECHANISM(
                    (CK_MECHANISM_TYPE)parameters.AlgID, 
                    mechanismParameters.Ptr, (CK_LONG)mechanismParameters.Size
                ); 
                // выполнить преобразование атрибутов
                using (AllocatedAttributes allocated = new AllocatedAttributes(attributes))
                {
	                // расшифровать ключ
	                Exception.Check(funcList.C_UnwrapKey(
		                (CK_SESSION_HANDLE)hSession, ref mechanism, 
                        (CK_OBJECT_HANDLE)hWrapKey, data, (CK_LONG)data.Length, 
		                allocated.Pointer, allocated.Count, out hKey
                    )); 
                }
            }
	        return hKey; 
        }
		///////////////////////////////////////////////////////////////////////////
		// Наследование ключа
		///////////////////////////////////////////////////////////////////////////
		public override ulong DeriveKey(ulong hSession, 
            Mechanism parameters, ulong hBaseKey, Attribute[] attributes)
        {
	        CK_OBJECT_HANDLE hKey = 0;

            // закодировать параметры алгоритма
            using (MechanismBuffer mechanismParameters = parameters.Encode(this))
            { 
	            // указать параметры алгоритма
	            API64.CK_MECHANISM mechanism = new API64.CK_MECHANISM(
                    (CK_MECHANISM_TYPE)parameters.AlgID, 
                    mechanismParameters.Ptr, (CK_LONG)mechanismParameters.Size
                ); 
                // выполнить преобразование атрибутов
                using (AllocatedAttributes allocated = new AllocatedAttributes(attributes))
                {
	                // наследовать ключ
	                Exception.Check(funcList.C_DeriveKey(
		                (CK_SESSION_HANDLE)hSession, ref mechanism, 
                        (CK_OBJECT_HANDLE)hBaseKey, allocated.Pointer, allocated.Count, out hKey
	                )); 
                }
            }
	        return hKey; 
        }
	};
}
