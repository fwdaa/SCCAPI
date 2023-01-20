using System;
using System.Windows.Forms;
using System.Collections.Generic;

namespace Aladdin.CAPI.GUI
{
	///////////////////////////////////////////////////////////////////////////
	// Диалог выбора аутентификации
	///////////////////////////////////////////////////////////////////////////
	public partial class AuthenticationDialog : Form
	{
        // функция перечисления аутентификаций
        public delegate Type[] AuthenticationCallback(string user); 
        // функция обработки
        public delegate object Callback(IWin32Window window, string user, Type[] authenticationTypes); 

        // функция перечисления аутентификаций и функция обработки
        private AuthenticationCallback authenticationCallback; private Callback callback; 

        // отобразить диалог для создания
		public static SecurityObject ShowCreate(IWin32Window parent, 
            CryptoProvider provider, SecurityInfo info, IRand rand, string user, 
            Type[] authenticationTypes, int attempts, params object[] pararameters)
		{
            // функция перечисления аутентификаций 
            AuthenticationCallback authenticationCallback = delegate(string userName)
            {
                // указать типы аутентификации
                return authenticationTypes; 
            }; 
            // функция обработки
            Callback callback = delegate (IWin32Window window, string userName, Type[] types)
            {
                // указать способ выбора аутентификации 
                AuthenticationSelector selector = new AuthenticationSelector(window, userName, attempts); 

                // указать генератор случайных данных
                using (IRand rebindRand = rand.CreateRand(window))
                { 
                    // создать объект с указанной аутентификацией
                    return selector.ShowCreate(provider, info, rebindRand, new List<Type>(types), pararameters); 
                }
            }; 
            // отобразить диалог
            return (SecurityObject)Show(parent, provider.Name, 
                info.FullName, user, authenticationCallback, callback
            ); 
		}
        // отобразить диалог 
		public static Credentials[] Show(IWin32Window parent, SecurityObject obj, string user, int attempts)
        {
            // функция перечисления аутентификаций 
            AuthenticationCallback authenticationCallback = delegate(string userName)
            {
                // инициализировать допустимые типы аутентификации
                List<Type> authenticationTypes = new List<Type>(); 

                // для всех поддерживаемых типов аутентификации
                foreach (Type authenticationType in obj.GetAuthenticationTypes(userName))
                {
                    // получить сервис аутентификации
                    AuthenticationService service = obj.GetAuthenticationService(userName, authenticationType); 

                    // добавить тип используемой аутентификации
                    if (service.CanLogin) authenticationTypes.Add(authenticationType); 
                }
                // указать типы аутентификации
                return authenticationTypes.ToArray(); 
            }; 
            // функция обработки
            Callback callback = delegate (IWin32Window window, string userName, Type[] authenticationTypes)
            {
                // указать способ выбора аутентификации 
                AuthenticationSelector selector = new AuthenticationSelector(window, userName, attempts); 

                // выполнить аутентификацию через кэш
                object result = ExecutionContext.CacheAuthenticate(obj, userName, authenticationTypes); 
                
                // показать диалог аутентификации
                return (result != null) ? result : selector.Show(obj, new List<Type>(authenticationTypes)); 
            }; 
            // отобразить диалог
            return (Credentials[])Show(parent, obj.Provider.Name, 
                obj.FullName, user, authenticationCallback, callback
            ); 
        }
        // отобразить диалог для изменения
		public static void ShowChange(IWin32Window parent, SecurityObject obj, string user, int attempts)
		{
            // функция перечисления аутентификаций 
            AuthenticationCallback authenticationCallback = delegate(string userName)
            {
                // инициализировать допустимые типы аутентификации
                List<Type> authenticationTypes = new List<Type>(); 

                // для всех поддерживаемых типов аутентификации
                foreach (Type authenticationType in obj.GetAuthenticationTypes(userName))
                {
                    // получить сервис аутентификации
                    AuthenticationService service = obj.GetAuthenticationService(userName, authenticationType); 

                    // добавить тип используемой аутентификации
                    if (service.CanChange) authenticationTypes.Add(authenticationType); 
                }
                // указать типы аутентификации
                return authenticationTypes.ToArray(); 
            }; 
            // указать функцию обработки
            Callback callback = delegate (IWin32Window window, string userName, Type[] authenticationTypes)
            {
                // указать способ выбора аутентификации 
                AuthenticationSelector selector = new AuthenticationSelector(window, userName, attempts); 

                // показать диалог смены аутентификации
                selector.ShowChange(obj, new List<Type>(authenticationTypes)); return null; 
            }; 
            // отобразить диалог
            Show(parent, obj.Provider.Name, obj.FullName, user, authenticationCallback, callback); 
		}
        // отобразить диалог 
		public static object Show(IWin32Window parent, string providerName, string containerName, 
            string user, AuthenticationCallback authenticationCallback, Callback callback)
        {
			// создать диалог ввода пароля
			AuthenticationDialog dialog = new AuthenticationDialog(
                providerName, containerName, user, authenticationCallback, callback
            ); 
            // отобразить диалог аутентификации
            DialogResult dialogResult = Aladdin.GUI.ModalView.Show(parent, dialog); 

			// проверить результат диалога
			if (dialogResult == DialogResult.OK) return dialog.Result;

			// при ошибке выбросить исключение
			throw new OperationCanceledException();
        }
        // конструктор
		private AuthenticationDialog() { InitializeComponent(); }

        // конструктор
		private AuthenticationDialog(string providerName, string containerName, 
            string user, AuthenticationCallback authenticationCallback, Callback callback) 
		{ 
			// сохранить переданные параметры
			InitializeComponent(); buttonOK.Enabled = false; this.result = null; 
            
			// сохранить переданные параметры
            this.authenticationCallback = authenticationCallback; this.callback = callback; 
            
			// установить имя провайдера и контейнера
			textBoxProvider.Text = providerName; textBoxContainer.Text = containerName;

            // установить имя пользователя
            if (user != null) { comboBoxUser.Text = user; comboBoxUser.Enabled = false; }

            // указать выбранный элемент
            else { comboBoxUser.SelectedIndex = 0; comboBoxUser.Enabled = true; }
        }
        private void OnUserTypeChanged(object sender, EventArgs e)
        {
            // инициализировать допустимые типы аутентификации
            List<Type> authenticationTypes = new List<Type>(
                authenticationCallback(comboBoxUser.Text)
            ); 
            // для всех типов аутентификации
            for (int i = 0; i < authenticationTypes.Count; i++)
            {
                // при допустимости парольной аутентификации
                if (typeof(Auth.PasswordCredentials).IsAssignableFrom(authenticationTypes[i]))
                {
                    // указать доступность выбора
                    checkBoxPassword.Enabled = true; checkBoxPassword.Checked = false; 

                    // указать выбор при осутствии вариантов
                    if (authenticationTypes.Count == 1) checkBoxPassword.Checked = true; 
                }
                // указать недоступность выбора
                else { checkBoxPassword.Enabled = checkBoxPassword.Checked = false; }

                // при допустимости биометрической аутентификации
                if (typeof(Auth.BiometricCredentials).IsAssignableFrom(authenticationTypes[i]))
                {
                    // указать доступность выбора
                    checkBoxBiometric.Enabled = true; checkBoxBiometric.Checked = false; 

                    // указать выбор при осутствии вариантов
                    if (authenticationTypes.Count == 1) checkBoxBiometric.Checked = true; 
                }
                // указать недоступность выбора
                else { checkBoxBiometric.Enabled = checkBoxBiometric.Checked = false; }
            }
        }
        private void OnAuthenticationChanged(object sender, EventArgs e)
        {
            // указать доступность кнопки
            buttonOK.Enabled = (checkBoxPassword.Checked || checkBoxBiometric.Checked); 
        }
		private void OnButtonOK(object sender, EventArgs e)
		{
            // выбранные типы аутентификации
            List<Type> authenticationTypes = new List<Type>(); 

            // заполнить выбранные типы аутентификации
            if (checkBoxPassword .Checked) authenticationTypes.Add(typeof(Auth.PasswordCredentials )); 
            if (checkBoxBiometric.Checked) authenticationTypes.Add(typeof(Auth.BiometricCredentials)); 

			// изменить форму курсора
			Cursor cursor  = Cursor.Current; Cursor.Current = Cursors.WaitCursor;

		    // сделать диалог недоступным
		    DialogResult = DialogResult.None; Enabled = false; 
            try { 
                // вызвать функцию обработки
                result = callback(this, comboBoxUser.Text, authenticationTypes.ToArray());

                // закрыть диалог
                DialogResult = DialogResult.OK;
			}
            // обработать отмену операции
            catch (OperationCanceledException) {} 
			catch (Exception ex) 
			{ 
				// вывести ее описание
				MessageBox.Show(this, ex.Message, Text, MessageBoxButtons.OK, MessageBoxIcon.Error); 
			}
			// восстановить форму курсора
			finally { Cursor.Current = cursor; Enabled = true; }
		}
		// результат выполнения 
		private object Result { get { return result; }} private object result;

        ///////////////////////////////////////////////////////////////////////////
        // Аутентификация выбираемого типа
        ///////////////////////////////////////////////////////////////////////////
        public class Authentication : DialogAuthentication
        {
            // описатель родительского окна и тип пользователя
            private IWin32Window parent; private string user; private int attempts; 

            // конструктор
            public Authentication(IWin32Window parent, string user, int attempts)
            {  
                // сохранить переданные параметры
                this.parent = parent; this.user = user; this.attempts = attempts; 
            } 
            // тип пользователя
            public override string User { get { return user; }}

            // тип аутентификации
            public override Type[] Types { get { return null; }}

            // выполнить локальную аутентификацию
            protected override Credentials[] LocalAuthenticate(SecurityObject obj)
            {
                // выполнить локальную аутентификацию
                return AuthenticationDialog.Show(parent, obj, user, attempts); 
            }
        }
	}
}
