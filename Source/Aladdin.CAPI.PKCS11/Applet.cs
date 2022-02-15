using System;
using System.IO;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis; 
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.PKCS11
{
	///////////////////////////////////////////////////////////////////////////////
	// Апплет на аппаратном устройстве
	///////////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
	public class Applet : ContainerStore, IRandFactory
	{
		// идентификатор считывателя, имя апплета и мсписок алгоритмов
		private UInt64 slotID; private String name; private List<UInt64> algIDs; 

		// конструктор
		public Applet(Token token, UInt64 slotID) : base(token)
        {
	        // получить информацию устройства
	        this.slotID = slotID; this.name = GetInfo().Model; 

            // получить список алгоритмов
            algIDs = new List<UInt64>(Module.GetAlgorithmList(slotID)); 
        }
		// интерфейс вызова функций
		public Module Module { get { return Provider.Module; }} 

		// криптографический провайдер
		public new Provider Provider { get { return Store.Provider; }}

		// смарт-карта апплета
		public new Token Store { get { return (Token)base.Store; }}

		// имя апплета
		public override object Name { get { return name; }}

		// получить информацию апплета
		public TokenInfo GetInfo() { return Module.GetTokenInfo(slotID); }

        // уникальный идентификатор
        public override string GetUniqueID() 
        { 
            // получить серийный номер апплета
            string serial = Arrays.ToHexString(GetInfo().SerialNumber); 
        
            // вернуть уникальный идентификатор
            return String.Format("{0}\\{1}", base.GetUniqueID(), serial); 
        }
		///////////////////////////////////////////////////////////////////////////
		// Аутентификация устройства
		///////////////////////////////////////////////////////////////////////////

		// проверить необходимость аутентификации
		public override bool IsAuthenticationRequired(System.Exception e)
        {
	        // проверить тип исключения
	        if (!(e is Aladdin.PKCS11.Exception)) return false; 
			
	        // определить код ошибки
	        uint code = (uint)((Aladdin.PKCS11.Exception)e).ErrorCode; 

	        // проверить код ошибки
	        return (code == API.CKR_USER_NOT_LOGGED_IN   ) || 
                   (code == API.CKR_TOKEN_WRITE_PROTECTED); 
        }
        // поддерживаемые типы аутентификации
		public override Type[] GetAuthenticationTypes(string user)
        { 
            // поддерживается парольная аутентификация
			return new Type[] { typeof(Auth.PasswordCredentials) }; 
        } 
        // получить сервис аутентификации
		public override AuthenticationService GetAuthenticationService(
			string user, Type authenticationType)
        {
            // проверить наличие парольной аутентификации
            if (!typeof(Auth.PasswordCredentials).IsAssignableFrom(authenticationType)) return null;   

	        // вернуть сервис аутентификации
	        return new PasswordService(this, user); 
        }
		// аутентификация устройства
		public void SetPassword(string user, string password) 
		{
			// указать парольную аутентификацию
			Authentication authentication = 
				new Auth.PasswordCredentials(user, password);

			// установить и выполнить аутентификацию
			Authentication = authentication; Authenticate();
		}
		// создать сеанс
		public Session OpenSession(ulong state)
        {
	        // указать тип пользователя
	        string user = (state == API.CKS_RW_SO_FUNCTIONS) ? "ADMIN" : "USER"; 

            // получить кэш аутентификации
	        CredentialsManager cache = ExecutionContext.GetProviderCache(Provider.Name); 
				
            // указать режим открытия 
            ulong mode = (state == API.CKS_RO_PUBLIC_SESSION || 
                          state == API.CKS_RO_USER_FUNCTIONS) ? 0 : API.CKF_RW_SESSION; 

	        // создать сеанс
	        using (Session session = new Session(Module, slotID, mode))
            {
                // получить состояние сеанса
                ulong sessionState = session.GetSessionInfo().State; 

	            // при необходимости аутентификации
	            if (state != API.CKS_RO_PUBLIC_SESSION && 
                    state != API.CKS_RW_PUBLIC_SESSION)
	            {
		            // проверить достижение состояния
		            if (sessionState == state) return RefObject.AddRef(session); 
	            }
				// получить аутентификацию из кэша
				Auth.PasswordCredentials credentials = (Auth.PasswordCredentials)
					cache.GetData(Info, user, typeof(Auth.PasswordCredentials)); 

                // проверить наличие аутентификации
                if (credentials != null) 
	            {
		            // сбросить текущую аутентификацию
		            if (sessionState != API.CKS_RO_PUBLIC_SESSION && 
			            sessionState != API.CKS_RW_PUBLIC_SESSION) session.Logout();

		            // при требовании аутентификации администратора
		            if (state == API.CKS_RW_SO_FUNCTIONS)
		            {
			            // установить аутентификацию
			            session.Login(API.CKU_SO, credentials.Password); 
		            }
		            else {
			            // установить аутентификацию
			            session.Login(API.CKU_USER, credentials.Password); 
		            }
					// вернуть сеанс
		            return RefObject.AddRef(session); 
                }
                // проверить допустимость состояния
                if (state == API.CKS_RO_PUBLIC_SESSION || state == API.CKS_RW_PUBLIC_SESSION)
                {
					// вернуть сеанс
		            return RefObject.AddRef(session); 
                }
            }
            // заново выполнить аутентификацию 
            Authenticate(); 
	
	        // создать сеанс
	        using (Session session = new Session(Module, slotID, mode))
            {
	            // получить состояние сеанса
                ulong sessionState = session.GetSessionInfo().State; 

	            // проверить достижение состояния
	            if (sessionState == state) return RefObject.AddRef(session); 

				// получить аутентификацию из кэша
				Auth.PasswordCredentials credentials =
					(Auth.PasswordCredentials)cache.GetData(
						Info, user, typeof(Auth.PasswordCredentials)
				);
				// проверить наличие аутентификации
				if (credentials == null) throw new InvalidOperationException();

	            // сбросить текущую аутентификацию
	            if (sessionState != API.CKS_RO_PUBLIC_SESSION && 
		            sessionState != API.CKS_RW_PUBLIC_SESSION) session.Logout();
            
	            // при требовании аутентификации администратора
	            if (state == API.CKS_RW_SO_FUNCTIONS)
	            {
		            // установить аутентификацию
		            session.Login(API.CKU_SO, credentials.Password); 
	            }
	            else {
		            // установить аутентификацию
		            session.Login(API.CKU_USER, credentials.Password); 
	            }
				// вернуть сеанс
	            return RefObject.AddRef(session); 
            }
        }
		///////////////////////////////////////////////////////////////////////////
		// Управление объектами
		///////////////////////////////////////////////////////////////////////////

		// перечислить контейнеры
		public override String[] EnumerateObjects()
        {
            // выделить память для списка контейнеров
            List<String> list = new List<String>(); 
            try {
				// выделить память для атрибутов поиска
				Attribute[] attributes = new Attribute[] { 

		            // указать признак нахождения на устройстве
		            Provider.CreateAttribute(API.CKA_TOKEN, API.CK_TRUE)
				};
				// открыть сеанс
				using (Session session = OpenSession(API.CKS_RO_PUBLIC_SESSION)) 
                {
					// для каждого объекта
					foreach (SessionObject obj in session.FindObjects(attributes))
					try {
						switch (obj.GetClass())
						{
						// для сертификата или открытого ключа
						case API.CKO_CERTIFICATE: case API.CKO_PUBLIC_KEY:
						{
							// определить имя контейнера
							string name = obj.GetLabel(); 

							// добавить имя в список
							if (!list.Contains(name)) list.Add(name); break; 
						}}
					}
					catch {}
				}
			}
            // обработать возможную ошибку
            catch {} return list.ToArray();
        }
		// создать контейнер
		public override SecurityObject CreateObject(IRand rand, 
			object name, object authenticationData, params object[] parameters)
		{
			// открыть контейнер
			return OpenObject(name, FileAccess.ReadWrite);
		}
		// открыть контейнер
		public override SecurityObject OpenObject(object name, FileAccess mode) 
        {
	        // указать режим открытия 
	        ulong modePKCS11 = (mode == FileAccess.ReadWrite) ? API.CKF_RW_SESSION : 0; 

	        // вернуть объект контейнера
	        return new Container(this, name.ToString(), modePKCS11); 
        }
		// удалить контейнер
		public override void DeleteObject(object name, Authentication[] authentications)
        {
            // открыть контейнер
            using (Container container = new Container(
                this, name.ToString(), API.CKF_RW_SESSION))
            { 
	            // удалить ключи
	            container.DeleteKeys(); 
            }
			// вызвать базовую функцию
			base.DeleteObject(name, authentications); 
        }
		///////////////////////////////////////////////////////////////////////////
		// Алгоритмы устройства
		///////////////////////////////////////////////////////////////////////////

		// получить список алгоритмов
		public UInt64[] Algorithms { get { return algIDs.ToArray(); }}

		// получить информацию об алгоритме
		public MechanismInfo GetAlgorithmInfo(ulong type)
		{
			// получить информацию об алгоритме
			return Module.GetAlgorithmInfo(slotID, type); 
		}
        // признак поддержки алгоритма
        public bool Supported(ulong type, ulong usage, int keySize)
        {
            // проверить поддержку алгоритма
            if (!algIDs.Contains(type)) return false; 
            
            // проверить необходимость последующих проверок
            if (usage == 0 && keySize == 0) return true; 
            try {
                // получить информацию алгоритма
                MechanismInfo info = GetAlgorithmInfo(type); 
            
                // проверить способ использования 
                if (usage != 0 && (info.Flags & usage) != usage) return false; 

                // проверить указание размера 
                if (keySize == 0) return true; 

                // проверить поддержку размера ключа
                return (info.MinKeySize <= keySize && keySize <= info.MaxKeySize); 
            }
            // обработать возможную ошибку
            catch { return false; }
        }
		// датчик случайных чисел
		public virtual IRand CreateRand(object window)
        {
	        // получить датчик случайных чисел
	        return new Rand(this, Provider.GenerateSeed(this), window); 
        }
		///////////////////////////////////////////////////////////////////////////
		// Объекты устройства
		///////////////////////////////////////////////////////////////////////////

		// найти объекты 
		public byte[][] GetKeyIDs(Session session, string label, KeyUsage keyUsage, bool set)
        {
	        KeyUsage signMask = KeyUsage.DigitalSignature | KeyUsage.CertificateSignature | 
		                        KeyUsage.CrlSignature     | KeyUsage.NonRepudiation; 
	        KeyUsage keyxMask = KeyUsage.KeyEncipherment  | KeyUsage.KeyAgreement; 
	
	        // создать список для найденных объектов
	        Dictionary<String, Byte[]> keyIDs = new Dictionary<String, Byte[]>();
			Dictionary<String, Byte[]> unkIDs = new Dictionary<String, Byte[]>();

			// для каждого найденного объекта
			foreach (SessionObject obj in session.FindTokenObjects(label, new Attribute[0]))
			{
				switch (obj.GetClass())
				{
				case API.CKO_CERTIFICATE: 
				{
					// получить идентификатор объекта
					byte[] id = obj.GetID(); string strID = Arrays.ToHexString(id);

					// назначение сертификата
					KeyUsage certUsage = KeyUsage.None;
					try	{ 
						// создать объект сертификата
						Certificate certificate = new Certificate(obj.GetValue());

						// сохранить назначение сертификата
						certUsage = certificate.KeyUsage;
					}
					// при отсутствии назначения
					catch {} if (certUsage == KeyUsage.None)
					{
						// добавить идентификатор в список
						if (!unkIDs.ContainsKey(strID)) unkIDs.Add(strID, id); break; 
					}
					// проверить совпадение атрибутов
					if ((keyUsage & certUsage) == (set ? certUsage : keyUsage))
					{
						// добавить идентификатор в список
						if (!keyIDs.ContainsKey(strID)) keyIDs.Add(strID, id);
					}
					break; 
				}
				case API.CKO_PUBLIC_KEY: 
				{
					// получить идентификатор объекта
					byte[] id = obj.GetID(); string strID = Arrays.ToHexString(id);

					// указать значения атрибутов по умолчанию
					Attribute[] attributesUsage = new Attribute[] {
						new Attribute(API.CKA_VERIFY), new Attribute(API.CKA_WRAP)
					};
					// получить атрибуты использования
					attributesUsage = obj.GetSafeAttributes(attributesUsage);

					// при отсутствии атрибутов
					if (attributesUsage[0].Value == null && attributesUsage[1].Value == null)
					{
						// добавить идентификатор в список
						if (!unkIDs.ContainsKey(strID)) unkIDs.Add(strID, id); break; 
					}
					// указать значения атрибутов по умолчанию
					KeyUsage decodedUsage = KeyUsage.None;

					// при использовании при проверке подписи
					if (attributesUsage[0].Value     != null && 
						attributesUsage[0].GetByte() != API.CK_FALSE)
					{
						// указать допустимость подписи
						decodedUsage = decodedUsage | signMask;
					}
					// при использовании при шифровании
					if (attributesUsage[1].Value     != null &&
						attributesUsage[1].GetByte() != API.CK_FALSE)
					{
						// указать допустимость обмена
						decodedUsage = decodedUsage | keyxMask;
					}
					// проверить совпадение атрибутов
					if ((keyUsage & decodedUsage) == (set ? decodedUsage : keyUsage))
					{
						// добавить идентификатор в список
						if (!keyIDs.ContainsKey(strID)) keyIDs.Add(strID, id);
					}
					break; 
				}}
			}
			// переключиться на объекты с неизвестным назначением
			if (keyIDs.Count == 0 && !set) keyIDs = unkIDs;

			// вернуть найденные объекты
			Byte[][] ids = new Byte[keyIDs.Count][]; keyIDs.Values.CopyTo(ids, 0); return ids; 
		}
		// найти объекты 
		public byte[][] GetKeyIDs(Session session, string label)
        {
			// создать список для найденных объектов
			Dictionary<String, Byte[]> keyIDs = new Dictionary<String, Byte[]>();

			// для каждого найденного объекта
			foreach (SessionObject obj in session.FindTokenObjects(label, new Attribute[0]))
			{
				switch (obj.GetClass())
				{
				case API.CKO_CERTIFICATE: case API.CKO_PUBLIC_KEY:
				{
					// получить идентификатор объекта
					byte[] id = obj.GetID(); string strID = Arrays.ToHexString(id);

					// добавить идентификатор в список
					if (!keyIDs.ContainsKey(strID)) keyIDs.Add(strID, id); break; 
				}}
			}
			// вернуть найденные объекты
			Byte[][] ids = new Byte[keyIDs.Count][]; keyIDs.Values.CopyTo(ids, 0); return ids;
        }
        ///////////////////////////////////////////////////////////////////////
        // Подготовится к генерации/записи ключевой пары
        ///////////////////////////////////////////////////////////////////////
		public byte[] PrepareKeyPair(Session session, 
            string label, byte[] keyID, IRand rand, KeyUsage keyUsage)
        {
            if (keyID != null)
            {
                // выделить память для атрибутов поиска
                Attribute[] attributes = new Attribute[] { new Attribute(API.CKA_ID, keyID) }; 

                // перечислить объекты контейнера
                SessionObject[] objects = session.FindTokenObjects(label, attributes);

               // удалить объекты контейнера
                foreach (SessionObject obj in objects) session.DestroyObject(obj);
            }
            else {
                // найти объекты для удаления
                byte[][] keyIDs = GetKeyIDs(session, label, keyUsage, true);

                // при наличии объектов для удаления
                for (int i = 0; i < keyIDs.Length; i++) 
                { 
                    // выделить память для атрибутов поиска
                    Attribute[] attributes = new Attribute[] { new Attribute(API.CKA_ID, keyIDs[i]) }; 

                    // перечислить объекты контейнера
                    SessionObject[] objects = session.FindTokenObjects(label, attributes);

                    // удалить объекты контейнера
                    foreach (SessionObject obj in objects) session.DestroyObject(obj);
                }
                // указать идентификатор ключа
                if (keyIDs.Length > 0) keyID = keyIDs[0];
            }
            // при отсутствии идентификатора
            if (keyID == null) { keyID = new byte[8]; 
                
                // сгенерировать идентификатор
                rand.Generate(keyID, 0, keyID.Length);

                // выделить память для атрибутов поиска
	            Attribute[] attributes = new Attribute[] { new Attribute(API.CKA_ID, keyID) }; 

                // перечислить объекты контейнера
		        while (session.FindTokenObjects(label, attributes).Length != 0)
                {
	                // сгенерировать идентификатор
                    rand.Generate(keyID, 0, keyID.Length);
	            }
            }
            return keyID; 
        }
	}
}
