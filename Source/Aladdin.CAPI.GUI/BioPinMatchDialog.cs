using System;
using System.Globalization;
using System.Collections.Generic;
using System.Windows.Forms;
using System.ComponentModel;

namespace Aladdin.CAPI.GUI
{
	///////////////////////////////////////////////////////////////////////////
	// Диалог регистрации отпечатков с вводом пин-кода
	///////////////////////////////////////////////////////////////////////////
    public partial class BioPinMatchDialog : Form
    {
        // используемый таймер и имена отпечатков пальцев
        private Timer timer; private Dictionary<Bio.Finger, String> fingerNames; 

        // отпечатки в элементе управления и элемент управления захватом отпечатка
        private Bio.Finger[] fingers; private Remoting.RemoteClientControl captureControl; 

		// объект контейнера и шаблон проверки отпечатка
		private SecurityObject obj; private int attempts; private Bio.MatchTemplate matchTemplate; 

        // отобразить диалог
		public static Credentials[] Show(IWin32Window parent, SecurityObject obj, string user, int attempts)
		{
			// создать диалог ввода пароля
			BioPinMatchDialog dialog = new BioPinMatchDialog(obj, user, attempts); 

            // отобразить диалог аутентификации
            DialogResult result = Aladdin.GUI.ModalView.Show(parent, dialog); 

			// проверить результат диалога
			if (result == DialogResult.OK) return dialog.Result;

			// при ошибке выбросить исключение
			throw new OperationCanceledException();
		}
        // конструктор
        private BioPinMatchDialog() { InitializeComponent(); }

        // конструктор
		public BioPinMatchDialog(SecurityObject obj, string user, int attempts) 
		{ 
			// сохранить переданные параметры
            InitializeComponent(); this.obj = obj; this.attempts = attempts; 
            
            // создать список имен пальцев
            fingerNames = new Dictionary<Bio.Finger, String>(); timer = new Timer();
   
            // заполнить список имен пальцев
            fingerNames.Add(Bio.Finger.LeftLittle , (string)comboFinger.Items[0]);  
            fingerNames.Add(Bio.Finger.LeftRing   , (string)comboFinger.Items[1]); 
            fingerNames.Add(Bio.Finger.LeftMiddle , (string)comboFinger.Items[2]); 
            fingerNames.Add(Bio.Finger.LeftIndex  , (string)comboFinger.Items[3]);
            fingerNames.Add(Bio.Finger.LeftThumb  , (string)comboFinger.Items[4]);
            fingerNames.Add(Bio.Finger.RightLittle, (string)comboFinger.Items[5]);
            fingerNames.Add(Bio.Finger.RightRing  , (string)comboFinger.Items[6]);
            fingerNames.Add(Bio.Finger.RightMiddle, (string)comboFinger.Items[7]);
            fingerNames.Add(Bio.Finger.RightIndex , (string)comboFinger.Items[8]);
            fingerNames.Add(Bio.Finger.RightThumb , (string)comboFinger.Items[9]);

            // инициализировать переменные
            Auth.BiometricService service = null; Result = null; comboFinger.Items.Clear();

			// установить имя провайдера и объекта
			textBoxProvider.Text = obj.Provider.Name; textBoxObject.Text = obj.FullName; 

            // установить имя пользователя
            if (user != null) { comboBoxUser.Text = user; comboBoxUser.Enabled = false;

                // получить биометрический сервис
                service = (Auth.BiometricService)obj.GetAuthenticationService(
                    user, typeof(Auth.BiometricCredentials)
                );
            }
            // указать выбранный элемент
            else { comboBoxUser.SelectedIndex = 0; comboBoxUser.Enabled = true;

                // получить биометрический сервис
                service = (Auth.BiometricService)obj.GetAuthenticationService(
                    comboBoxUser.Text, typeof(Auth.BiometricCredentials)
                );
            }
			// для всех считывателей
			foreach (string reader in service.Provider.EnumerateReaders()) 
			{
				// добавить считыватель в список
				comboReader.Items.Add(reader);
			}
			// выбрать считыватель по умолчанию
            if (comboReader.Items.Count > 0) comboReader.SelectedIndex = 0;
        }
        // инициализация диалога
		private void OnLoad(object sender, EventArgs e)
		{
			// установить начальные условия
			buttonStop.Enabled = buttonOK.Enabled = false; 

			// установить начальные условия
			buttonStart.Enabled = (comboFinger.SelectedIndex >= 0); 

			// запустить таймер 
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
			// изменить доступность элементов управления
            buttonOK.Enabled = (attempts > 0)  && (matchTemplate != null) && (textBoxPIN.Text.Length > 0); 
		}
        private class FingerComparer : IComparer<Bio.Finger>  
        {
            // упорядочить отпечатки
            public int Compare(Bio.Finger x, Bio.Finger y) { return (int)x - (int)y; }
        }
        private void OnUserChanged(object sender, EventArgs e)
        {
            // указать отсутствие выбора пальца
            comboFinger.SelectedIndex = -1; 

            // получить биометрический сервис объекта
            Auth.BiometricService service = (Auth.BiometricService)
                obj.GetAuthenticationService(
                    comboBoxUser.Text, typeof(Auth.BiometricCredentials)
            ); 
            // получить допустимые отпечатки пальцев
            fingers = service.GetAvailableFingers(); 
            
            // отсортировать допустимые отпечатки пальцев
            Array.Sort(fingers, Comparer<Bio.Finger>.Default); 

            // для всех возможных пальцев
            for (int i = 0; i < fingers.Length; i++)
            {
                // указать имя отпечатка
                comboFinger.Items.Add(fingerNames[fingers[i]]); 
            }
        }
        private void OnFingerChanged(object sender, EventArgs e)
        {
			// указать доступность кнопки
			buttonStart.Enabled = (comboFinger.SelectedIndex >= 0); 

            // указать недоступность изображения 
            textInfo.Text = String.Empty; imageFinger.Visible = false; 
        }
        private void OnQualityScroll(object sender, EventArgs e)
        {
            // указать значение качества отпечатка
            labelQualityValue.Text = String.Format("{0} %", trackBarQuality.Value); 
        }
 	    private bool OnCheckImage(Bio.Image image)
		{
            // проверить качество отпечатка
			if (image.Quality >= trackBarQuality.Value) return true; 
            
            // установить текст            
            textInfo.Text = Resource.MessageFingerQuality; return false;
		}
		private void OnStart(object sender, EventArgs e)
		{
            // получить биометрический сервис объекта
            Auth.BiometricService service = (Auth.BiometricService)
                obj.GetAuthenticationService(
                    comboBoxUser.Text, typeof(Auth.BiometricCredentials)
            ); 
			// получить выбранный считыватель
			using (Bio.Reader reader = service.Provider.OpenReader(comboReader.SelectedItem.ToString()))
			try {
			    // вывести сообщение
			    textInfo.Text = Resource.MessageFingerTouch; buttonStop.Enabled = true;

			    // изменить доступность элементов управления
			    buttonStart.Enabled = comboReader.Enabled = comboFinger.Enabled = false; 

                // указать обработчик
                Remoting.IBackgroundHandler handler = 
                    new Remoting.BackgroundHandler(AfterVerify, null); 

                // запустить поток сканирования
                captureControl = reader.BeginCapture(
                    Bio.ImageTarget.Match, OnCheckImage, new TimeSpan(0), handler
                ); 
			}
			// обработать возможную ошибку
			catch (Exception ex) { matchTemplate = null; AfterStop(ex.Message); } 
		}
        // отменить операцию
		private void OnStop(object sender, EventArgs e) 
        { 
            // отменить операцию
            captureControl.Cancel(); captureControl.Dispose(); 
        }
 		private void AfterVerify(object sender, RunWorkerCompletedEventArgs e)
		{
            // освободить выделенные ресурсы
            captureControl.Dispose();

            // обработать возникшее исключение
            if (e.Error != null) { matchTemplate = null; AfterStop(e.Error.Message); return; } 

            // при отмене операции
            if (e.Cancelled) { matchTemplate = null; 
                
                // обработать отмену операции
                AfterStop(new OperationCanceledException().Message); return; 
            } 
            // получить биометрический сервис объекта
            Auth.BiometricService service = (Auth.BiometricService)
                obj.GetAuthenticationService(
                    comboBoxUser.Text, typeof(Auth.BiometricCredentials)
            ); 
            try { 
                // получить текущий выбранный палец
                Bio.Finger finger = fingers[comboFinger.SelectedIndex]; 
                
                // получить изображение отпечатка
                Bio.Image image = (Bio.Image)e.Result;

				// заполнить текущий отпечаток
				imageFinger.Image = (System.Drawing.Image)
                    image.GetThumbnailImage(imageFinger.Width, imageFinger.Height); 

                // обновить изображение
                imageFinger.Visible = true; imageFinger.Refresh(); 
                
                // создать шаблон для проверки отпечатка
                matchTemplate = service.CreateTemplate(finger, image); 
                
                // вывести сообщение о готовности отпечатка
                AfterStop(Resource.MessageFingerCaptured); 
            }
			// обработать возможную ошибку
			catch (Exception ex) { AfterStop(ex.Message); }
        }
		private void AfterStop(string message)
		{
			// указать сообщение
			textInfo.Text = message; buttonStop.Enabled = false; 

			// изменить доступность элементов управления
            buttonOK.Enabled = (attempts > 0) && (matchTemplate != null) && (textBoxPIN.Text.Length > 0); 

			// изменить доступность элементов управления
			buttonStart.Enabled = comboReader.Enabled = comboFinger.Enabled = true; 
		} 
		private void OnButtonOK(object sender, EventArgs e)
		{
			// изменить состояние курсора
			Cursor cursor = Cursor.Current; Cursor.Current = Cursors.WaitCursor; 
            
            // отменить закрытие диалога
            DialogResult = DialogResult.None; 
			try { 
                // указать используемые аутентификации
                Authentication bioAuthentication = new Auth.BiometricCredentials(
                    comboBoxUser.Text, matchTemplate  
                ); 
                Authentication pinAuthentication = new Auth.PasswordCredentials(
                    comboBoxUser.Text, textBoxPIN.Text
                ); 
                // выполнить аутентификацию
                Credentials[] bioCredentials = bioAuthentication.Authenticate(obj);
                Credentials[] pinCredentials = pinAuthentication.Authenticate(obj); 

                // сохранить выполненные аутентификации
                Result = new Credentials[] { bioCredentials[0], pinCredentials[0] }; 
                
                // закрыть диалог
                DialogResult = DialogResult.OK;
			}
			// при ошибке вывести ее описание
			catch (Exception ex) { Aladdin.GUI.ErrorDialog.Show(this, ex); 

                // установить недоступной кноку OK
				if (--attempts <= 0) buttonOK.Enabled = false; 
            }

			// восстановить состояние курсора
			finally { Cursor.Current = cursor; }
		}
		// результат выполнения протокола
		private Credentials[] Result { get; set; }

        ///////////////////////////////////////////////////////////////////////////
        // Биометрическая аутентификация с указанием пароля
        ///////////////////////////////////////////////////////////////////////////
        public class BioPinDialogAuthentication : DialogAuthentication
        {
            // описатель родительского окна и тип пользователя
            private IWin32Window parent; private string user; private int attempts; 

            // конструктор
            public BioPinDialogAuthentication(IWin32Window parent, string user, int attempts)
            { 
                // сохранить переданные параметры
                this.parent = parent; this.user = user; this.attempts = attempts; 
            }
            // тип пользователя
            public override string User { get { return user; }}

            // тип аутентификации
            public override Type[] Types { get 
            { 
                // тип аутентификации
                return new Type[] { typeof(Auth.PasswordCredentials ), 
                                    typeof(Auth.BiometricCredentials) };
            }}
            // выполнить локальную аутентификацию
            protected override Credentials[] LocalAuthenticate(SecurityObject obj)
            {
                // выполнить локальную аутентификацию
                return BioPinMatchDialog.Show(parent, obj, user, attempts); 
            }
        }
    }
}
