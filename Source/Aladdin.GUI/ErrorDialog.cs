using System;
using System.Drawing;
using System.Windows.Forms;

namespace Aladdin.GUI
{
	//////////////////////////////////////////////////////////////////////////////
	// диалог сообщения об ошибке
	//////////////////////////////////////////////////////////////////////////////
	public partial class ErrorDialog : Form
	{
		// показать сообщение об ошибке
		public static void Show(IntPtr hParent, string title, Exception exception)
		{
			// проверить наличие описателя окна
			if (hParent == IntPtr.Zero) { Show(title, exception); return; }

			// указать используемое окно
			IWin32Window parent = new Win32Window(hParent); 

			// показать сообщение об ошибке
			new ErrorDialog(title, exception).ShowDialog(parent); 
		}
		// показать сообщение об ошибке
		public static void Show(string title, Exception exception)
		{
			// показать сообщение об ошибке
			new ErrorDialog(title, exception).ShowDialog(); 
		}
		// показать сообщение об ошибке
		public static void Show(Form form, Exception exception)
		{
			// показать сообщение об ошибке
			new ErrorDialog(form.Text, exception).ShowDialog(form); 
		}
		// родительское окно и описание исключения
		private string title; private Exception exception; 
		
		// позиция элементов управления
		private Size formSize; private Point buttonLocation;

		// конструктор
		public ErrorDialog() { InitializeComponent(); } 

		// конструктор
		public ErrorDialog(string title, Exception exception) 
		{ 
			// сохранить переданные параметры
			InitializeComponent(); this.title = title; this.exception = exception; 
		}
		private void ErrorDialog_Load(object sender, EventArgs e)
		{
			// установить имя диалога и создать растровое изображение
			Text = title; Icon icon = SystemIcons.Error; pictureBox.Image = new Bitmap(icon.Width, icon.Height); 

			// заполнить растровое изображение
			using (Graphics graphics = Graphics.FromImage(pictureBox.Image)) graphics.DrawIcon(icon, 0, 0);

			// сохранить позицию элементов управления
			formSize = Size; buttonLocation = buttonOK.Location; 
			
			// установить значения по умолчанию
			int delta = 0; checkBox.Checked = false; textBoxDetails.Visible = false; 

			// установить текст ошибки
			textBoxError.Text = exception.Message; textBoxDetails.Text = exception.StackTrace; 

			// определить число строк сообщения
			IntPtr result = NativeMethods.SendMessage(textBoxError.Handle, 0xBA, IntPtr.Zero, IntPtr.Zero); 

			// в зависимости от количества строк
			int lines = result.ToInt32(); if (lines > 20) lines = 20; if (lines > 2)
			{
				// определить изменение размера 
				delta  = textBoxError.Height / 2 * lines - textBoxError.Height; 
			}
			// изменить размер диалога
			Size = new Size(Size.Width, Size.Height + delta); 

			// изменить размер текстового поля
			textBoxError.Height = textBoxError.Height + delta; 

			// изменить позицию кнопок
			checkBox.Location = new Point(checkBox.Location.X, checkBox.Location.Y + delta); 
			buttonOK.Location = new Point(buttonOK.Location.X, buttonOK.Location.Y + delta); 

			// изменить позицию текстового поля
			textBoxDetails.Location = new Point(textBoxDetails.Location.X, textBoxDetails.Location.Y + delta); 

			// сохранить вычисленные размеры
			formSize = Size; buttonLocation = buttonOK.Location; 
			
			// скрыть дополнительную информацию
			checkBox_CheckedChanged(this, EventArgs.Empty); 
		}
		private void checkBox_CheckedChanged(object sender, EventArgs e)
		{
			// установить видимость дополнительных данных
			textBoxDetails.Visible = checkBox.Checked; 

			// отобразить полный диалог
			if (checkBox.Checked) { Size = formSize; buttonOK.Location = buttonLocation; }
			else { 
				// определить изменение размера 
				int delta  = textBoxDetails.Height + textBoxDetails.Margin.Top + textBoxDetails.Margin.Bottom; 
				    delta += checkBox      .Height + checkBox      .Margin.Top + checkBox      .Margin.Bottom; 

				// сдвинуть кнопку OK
				buttonOK.Location = new Point(buttonOK.Location.X, buttonOK.Location.Y - delta);

				// уменьшить размер диалога
				Size = new Size(Size.Width, Size.Height - delta); 
			}
		}
	}
}
