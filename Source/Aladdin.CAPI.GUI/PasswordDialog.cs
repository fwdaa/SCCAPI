using System;
using System.Globalization;
using System.Windows.Forms;

namespace Aladdin.CAPI.GUI
{
	///////////////////////////////////////////////////////////////////////////
	// Диалог ввода пароля
	///////////////////////////////////////////////////////////////////////////
	public partial class PasswordDialog : Form
	{
		// защищенный объект и используемый таймер 
		private SecurityObject obj; private Timer timer; private int attempts; 

        // отобразить диалог
		public static Credentials[] Show(IWin32Window parent, SecurityObject obj, string user, int attempts)
		{
			// создать диалог ввода пароля
			PasswordDialog dialog = new PasswordDialog(obj, user, attempts); 

            // отобразить диалог аутентификации
            DialogResult result = Aladdin.GUI.ModalView.Show(parent, dialog); 

			// проверить результат диалога
			if (result == DialogResult.OK) return dialog.Result;

			// при ошибке выбросить исключение
			throw new OperationCanceledException();
		}
        // конструктор
		private PasswordDialog() { InitializeComponent(); }

        // конструктор
		private PasswordDialog(SecurityObject obj, string user, int attempts) 
		{ 
			// сохранить переданные параметры
			InitializeComponent(); this.obj = obj; this.attempts = attempts; 

            // установить имя провайдера
			textBoxProvider.Text = obj.Provider.Name; Result = null;

			// установить имя контейнера
			textBoxContainer.Text = obj.FullName; buttonOK.Enabled = false;

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
			timer.Tick += OnTick; timer.Start(); 
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
			// проверить наличие пароля 
			buttonOK.Enabled = (attempts > 0 && textBoxPassword.Text.Length > 0); 
        }
		private void OnButtonOK(object sender, EventArgs e)
		{
			// изменить форму курсора
			Cursor cursor  = Cursor.Current; Cursor.Current = Cursors.WaitCursor; 

		    // сделать диалог недоступным
		    DialogResult = DialogResult.None; Enabled = false; timer.Stop(); 
            try { 
                // указать используемый протокол
                CAPI.Authentication authentication = 
                    new Auth.PasswordCredentials(comboBoxUser.Text, textBoxPassword.Text); 

				// выполнить аутентификацию и закрыть диалог
				Result = authentication.Authenticate(obj); DialogResult = DialogResult.OK;
			} 
			// при ошибке 
			catch (Exception ex) 
			{ 
				// вывести ее описание
				MessageBox.Show(this, ex.Message, Text, MessageBoxButtons.OK, MessageBoxIcon.Error); 

				// установить недоступной кноку OK
				if (--attempts <= 0) buttonOK.Enabled = false; 
			}
			// восстановить форму курсора
			finally { timer.Start(); Enabled = true; Cursor.Current = cursor; }
		}
		// результат выполнения установки пароля
		private Credentials[] Result { get; set; }

        ///////////////////////////////////////////////////////////////////////////
        // Парольная аутентификация
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
            public override Type[] Types
            {
                // тип аутентификации
                get { return new Type[] { typeof(Auth.PasswordCredentials) }; }
            }
            // выполнить локальную аутентификацию
            protected override Credentials[] LocalAuthenticate(SecurityObject obj)
            {
                // выполнить локальную аутентификацию
                return PasswordDialog.Show(parent, obj, user, attempts); 
            }
        }
    }
}
