using System;
using System.Windows.Forms;

namespace Aladdin.GUI
{
	///////////////////////////////////////////////////////////////////////////
	// Узел пользовательского интерфейса
	///////////////////////////////////////////////////////////////////////////
	public class ConsoleNode
	{
		public readonly ConsoleForm		    MainForm;	// основное окно
		public readonly ConsoleNode		    Parent;		// родительский элемент
		public readonly ConsoleForm.Node	Node;		// логический элемент
		public readonly TreeNode		    TreeNode;	// элемент дерева
		public readonly ListViewItem	    ListNode;	// элемент списка

		// конструктор
		internal ConsoleNode(ConsoleForm form, ConsoleForm.Node node)
		{
			// сохранить элементы
			MainForm = form; Parent = null; Node = node;

			// создать узел для иерархического дерева
			TreeNode = new TreeNode(node.Label); TreeNode.Tag = this;

			// создать узел для списка элементов
			ListNode = new ListViewItem(node.Label); ListNode.Tag = this;
		}
		// конструктор
		internal ConsoleNode(ConsoleNode parent, ConsoleForm.Node node) 
		{ 
			// сохранить элементы
			MainForm = parent.MainForm; Parent = parent; Node = node; 

			// создать узел для иерархического дерева
			TreeNode = new TreeNode(node.Label); TreeNode.Tag = this;

			// создать узел для списка элементов
			ListNode = new ListViewItem(node.Label); ListNode.Tag = this;
		}
		// обновить узел
		public ConsoleNode[] Refresh() { return MainForm.RefreshNode(this); }

		// выделить узел
		public void Select() { MainForm.SelectNode(this); }
	}
}
