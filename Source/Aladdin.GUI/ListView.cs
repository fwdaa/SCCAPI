using System;
using System.Drawing;
using System.Windows.Forms;
using System.ComponentModel;
using System.Collections.Generic;
using System.Security;
using System.Security.Permissions;

namespace Aladdin.GUI
{
	//////////////////////////////////////////////////////////////////////////////
	// Список элементов с возможностью сортировки
	//////////////////////////////////////////////////////////////////////////////
	public partial class ListView : System.Windows.Forms.ListView
	{
		///////////////////////////////////////////////////////////////////////
		// Конструктор
		///////////////////////////////////////////////////////////////////////
		public ListView() { labelTip = false; EmptyMessage = String.Empty; 
			
			// добавить обработчик события
			ColumnClick += new ColumnClickEventHandler(OnColumnClick); 
		}
		// создать объект сортировки
		private ItemComparer itemComparer = new ItemComparer();

		///////////////////////////////////////////////////////////////////////
		// Обработчик события сортировки
		///////////////////////////////////////////////////////////////////////
		public void SortColumn(int columnIndex, bool sortAscending)
		{
			// указать столбец и направление для сортировки
			itemComparer.ColumnIndex = columnIndex; itemComparer.SortAscending = sortAscending;

			// произвести сортировку
			ListViewItemSorter = itemComparer; ListViewItemSorter = null;
		}
		protected void OnColumnClick(object sender, ColumnClickEventArgs e)
		{
			// указать столбец для сортировки
			itemComparer.ColumnIndex = e.Column;

			// произвести сортировку
			ListViewItemSorter = itemComparer; ListViewItemSorter = null;
		}
		///////////////////////////////////////////////////////////////////////
		// Определение свойств
		///////////////////////////////////////////////////////////////////////
		[DefaultValue(true)]
		public bool LabelTip { get { return labelTip; } 
			
			// установить признак использования подсказки
			set { UpdateExtendedStyles(value); labelTip = value; }
		}
		public string EmptyMessage { get; set; } private bool labelTip; 

		///////////////////////////////////////////////////////////////////////
		// Встраивание дополнительной логики при создании списка
		///////////////////////////////////////////////////////////////////////
		protected override void OnHandleCreated(EventArgs e)
		{
			base.OnHandleCreated(e); UpdateExtendedStyles(labelTip);
		}
		protected void UpdateExtendedStyles(bool labelTip)
		{
			if (!IsHandleCreated) return; const int styleTip = 0x4000; 

			IntPtr style = NativeMethods.SendMessage(Handle,
				NativeMethods.LVM_GETEXTENDEDLISTVIEWSTYLE, IntPtr.Zero, IntPtr.Zero
			);
			int value = (labelTip) ? style.ToInt32() | styleTip : style.ToInt32() ^ styleTip; 

			NativeMethods.SendMessage(Handle,
				NativeMethods.LVM_SETEXTENDEDLISTVIEWSTYLE, IntPtr.Zero, new IntPtr(value)
			);
			Invalidate();
		}
        [SecurityPermission(SecurityAction.LinkDemand, UnmanagedCode = true)]
        protected override void WndProc(ref Message m)
		{
			base.WndProc(ref m); if (Items.Count != 0) return;

			if (m.Msg == NativeMethods.WM_MOVE) { Invalidate(); return; }
			if (m.Msg == NativeMethods.WM_SIZE) { Invalidate(); return; }

			if (m.Msg != NativeMethods.WM_PAINT) return;

			Graphics graphics = Graphics.FromHwnd(m.HWnd); graphics.Clear(BackColor);

			SizeF sizeString = graphics.MeasureString(EmptyMessage, Font);

			float x = ClientRectangle.Left + (ClientSize.Width - sizeString.Width) / 2;
			float y = sizeString.Height / 2;

			IntPtr header = NativeMethods.SendMessage(m.HWnd, 
				NativeMethods.LVM_GETHEADER, IntPtr.Zero, IntPtr.Zero
			);
			if (NativeMethods.IsWindowVisible(header))
			{
				NativeMethods.RECT rect;
				NativeMethods.GetWindowRect(header, out rect);

				y += rect.bottom - rect.top;
			}
			graphics.DrawString(EmptyMessage, Font, new SolidBrush(ForeColor), x, y);
		}
		///////////////////////////////////////////////////////////////////////
		// Сравнение элементов
		///////////////////////////////////////////////////////////////////////
		class ItemComparer : System.Collections.IComparer, IComparer<ListViewItem>
		{
			// номер столбца и направление сортировки
			private int columnIndex = 0; private bool sortAscending = true;	

			// указать столбец для сортировки
			public int ColumnIndex { set
			{
				// изменить направление сортировки
				if (value == columnIndex) sortAscending = !sortAscending;
				else {
					// установить номер столбца
					columnIndex = value; sortAscending = true;
				}
			}}
			// указать направление сортировки
			public bool SortAscending { set { sortAscending = value; }}

			// сравнение элементов
			public int Compare(object x, object y)
			{
				// сравнить элементы
				return Compare((ListViewItem)x, (ListViewItem)y);
			}
			// сравнение элементов
			public int Compare(ListViewItem x, ListViewItem y)
			{
				// проверить корректность
				if (x.SubItems.Count <= columnIndex) return 0;
				if (y.SubItems.Count <= columnIndex) return 0;

				// получить текстовые значения элементов
				string value1 = x.SubItems[columnIndex].Text;
				string value2 = y.SubItems[columnIndex].Text;

				// сравнить значения элементов
				return String.Compare(value1, value2) * (sortAscending ? 1 : -1);
			}
		}
	}
}
