using System;
using System.Globalization;
using System.Windows.Forms;

namespace Aladdin.CAPI.GUI
{
	///////////////////////////////////////////////////////////////////////////
	// Диалог ввода пароля
	///////////////////////////////////////////////////////////////////////////
	public partial class PasswordChangeDialog : Form
	{
        // функция обработки
        public delegate object Callback(IWin32Window window, string user, string password); 

		// используемый таймер и функция обработки
		private System.Windows.Forms.Timer timer; private Callback callback; 

        // отобразить диалог для создания
		public static SecurityObject ShowCreate(IWin32Window parent, 
            IProvider provider, SecurityInfo info, IRand rand, string user, params object[] parameters)
		{
            // функция обработки
            Callback callback = delegate (IWin32Window window, string userName, string password)
            {
                // указать способ выбора аутентификации 
                AuthenticationSelector selector = new AuthenticationSelector(window, userName); 

				// указать генератор случайных данных
				using (IRand rebindRand = new Rand(rand, window))
				{ 
					// создать контейнер
					return selector.CreateObject(provider, info.Scope, rebindRand, info.FullName, password, parameters); 
				}
            }; 
            // отобразить диалог
            return (SecurityObject)Show(parent, provider.Name, info.FullName, user, callback); 
		}
        // отобразить диалог для изменения
		public static Credentials ShowChange(IWin32Window parent, SecurityObject obj, string user)
		{
            // функция обработки
            Callback callback = delegate (IWin32Window window, string userName, string password)
            {
                // указать тип аутентификации
                Type authenticationType = typeof(Auth.PasswordCredentials); 

                // получить сервис аутентификации
                Auth.PasswordService service = (Auth.PasswordService)
                    obj.GetAuthenticationService(userName, authenticationType); 

                // изменить пароль
                return service.Change(password); 
            }; 
            // отобразить диалог
            return (Credentials)Show(parent, obj.Provider.Name, obj.FullName, user, callback); 
		}
        // отобразить диалог для создания
		public static object Show(IWin32Window parent, 
            string providerName, string containerName, string user, Callback callback)
		{
			// создать диалог ввода пароля
			PasswordChangeDialog dialog = new PasswordChangeDialog(
                providerName, containerName, user, callback
            ); 
            // отобразить диалог аутентификации
            DialogResult result = Aladdin.GUI.ModalView.Show(parent, dialog); 

			// проверить результат диалога
			if (result == DialogResult.OK) return dialog.Result;

			// при ошибке выбросить исключение
			throw new OperationCanceledException();
		}
        // конструктор
		private PasswordChangeDialog() { InitializeComponent(); }

        // конструктор
		private PasswordChangeDialog(string providerName, 
            string containerName, string user, Callback callback) 
		{ 
			// сохранить переданные параметры
			InitializeComponent(); buttonOK.Enabled = false;  
            
			// сохранить переданные параметры
            this.callback = callback; Result = null;

			// установить имя провайдера и контейнера
			textBoxProvider.Text = providerName; textBoxContainer.Text = containerName;

			// установить имя пользователя
			if (user != null) { comboBoxUser.Text = user; comboBoxUser.Enabled = false; }

			// указать выбранный элемент
			else { comboBoxUser.SelectedIndex = 0; comboBoxUser.Enabled = true; }
		}
		// инициализация диалога
		private void OnLoad(object sender, EventArgs e)
		{
            // создать таймер
            timer = new System.Windows.Forms.Timer();

			// создать таймер 
			timer.Tick += OnTick; timer.Start(); buttonOK.Enabled = false; 
		}
		private void OnTick(object sender, EventArgs e)
		{
			// получить идентификатор языка
			CultureInfo cultureInfo = new CultureInfo(
                (int)NativeMethods.GetKeyboardLayout(0).ToInt64() & 0xFFFF
            ); 
			// установить абревиатуру языка
			textBoxLang.Text = cultureInfo.TwoLetterISOLanguageName.ToUpper(); 
		}
		private void OnPasswordChanged(object sender, EventArgs e)
		{
			// указать доступность элемента управления
			buttonOK.Enabled = textBoxPassword .Text.Length > 0 && 
                               textBoxPassword2.Text.Length > 0; 
		}
		private void OnButtonOK(object sender, EventArgs e)
		{
            // проверить совпадение паролей
            if (textBoxPassword.Text != textBoxPassword2.Text)
            {
    	        // вывести описание ошибки
		        MessageBox.Show(this, Resource.ErrorPasswordMismatch, 
                    Text, MessageBoxButtons.OK, MessageBoxIcon.Error
                ); 
                // установить фокус на элемент
                textBoxPassword.Focus(); return; 
            }
			// изменить форму курсора
			Cursor cursor  = Cursor.Current; Cursor.Current = Cursors.WaitCursor;

		    // сделать диалог недоступным
		    DialogResult = DialogResult.None; Enabled = false; timer.Stop(); 
            try { 
                // выполнить функцию обработки
                Result = callback(this, comboBoxUser.Text, textBoxPassword.Text); 

                // указать закрытие диалога
                DialogResult = DialogResult.OK;
			} 
			// при ошибке 
			catch (Exception ex) 
			{ 
				// вывести ее описание
				MessageBox.Show(this, ex.Message, Text, MessageBoxButtons.OK, MessageBoxIcon.Error); 
			}
			// восстановить форму курсора
			finally { timer.Start(); Enabled = true; Cursor.Current = cursor; }
		}
		// результат выполнения 
		private object Result { get; set; } 
    }
}
