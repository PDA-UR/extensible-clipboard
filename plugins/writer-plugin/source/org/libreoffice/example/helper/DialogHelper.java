package org.libreoffice.example.helper;

import java.io.File;

import com.sun.star.awt.MessageBoxType;
import com.sun.star.awt.Point;
import com.sun.star.awt.XButton;
import com.sun.star.awt.XComboBox;
import com.sun.star.awt.XControl;
import com.sun.star.awt.XControlContainer;
import com.sun.star.awt.XControlModel;
import com.sun.star.awt.XDialog;
import com.sun.star.awt.XDialogEventHandler;
import com.sun.star.awt.XDialogProvider2;
import com.sun.star.awt.XFixedText;
import com.sun.star.awt.XListBox;
import com.sun.star.awt.XMessageBox;
import com.sun.star.awt.XMessageBoxFactory;
import com.sun.star.awt.XTextComponent;
import com.sun.star.awt.XToolkit;
import com.sun.star.awt.XWindow;
import com.sun.star.awt.XWindowPeer;
import com.sun.star.awt.tree.XTreeControl;
import com.sun.star.beans.PropertyVetoException;
import com.sun.star.beans.UnknownPropertyException;
import com.sun.star.beans.XPropertySet;
import com.sun.star.lang.WrappedTargetException;
import com.sun.star.uno.AnyConverter;
import com.sun.star.uno.Exception;
import com.sun.star.uno.UnoRuntime;
import com.sun.star.uno.XComponentContext;

public class DialogHelper {

	public static String[] SupportedWindowNames = { "FooOptionsPage" };

	/**
	 * Create a dialog from an xdl file.
	 *
	 * @param xdlFile The filename in the `dialog` folder
	 * @param context
	 * @return XDialog
	 */
	public static XDialog createDialog(String xdlFile, XComponentContext context, XDialogEventHandler handler) {
		Object oDialogProvider;
		try {
			oDialogProvider = context.getServiceManager().createInstanceWithContext("com.sun.star.awt.DialogProvider2",
					context);
			XDialogProvider2 xDialogProv = (XDialogProvider2) UnoRuntime.queryInterface(XDialogProvider2.class,
					oDialogProvider);
			File dialogFile = FileHelper.getDialogFilePath(xdlFile, context);
			return xDialogProv.createDialogWithHandler(convertToURL(context, dialogFile), handler);
		} catch (Exception e) {
			return null;
		}
	}

	/** Returns a URL to be used with XDialogProvider to create a dialog */
	public static String convertToURL(XComponentContext xContext, File dialogFile) {
		String sURL = null;
		try {
			com.sun.star.ucb.XFileIdentifierConverter xFileConverter = (com.sun.star.ucb.XFileIdentifierConverter) UnoRuntime
					.queryInterface(com.sun.star.ucb.XFileIdentifierConverter.class, xContext.getServiceManager()
							.createInstanceWithContext("com.sun.star.ucb.FileContentProvider", xContext));
			sURL = xFileConverter.getFileURLFromSystemPath("", dialogFile.getAbsolutePath());
		} catch (com.sun.star.uno.Exception ex) {
			return null;
		}
		return sURL;
	}

	/** Returns a button (XButton) from a dialog */
	public static XButton getButton(XDialog dialog, String componentId) {
		XControlContainer xDlgContainer = (XControlContainer) UnoRuntime.queryInterface(XControlContainer.class,
				dialog);
		Object control = xDlgContainer.getControl(componentId);
		return (XButton) UnoRuntime.queryInterface(XButton.class, control);
	}

	/** Returns a text field (XTextComponent) from a dialog */
	public static XTextComponent getEditField(XDialog dialog, String componentId) {
		XControlContainer xDlgContainer = (XControlContainer) UnoRuntime.queryInterface(XControlContainer.class,
				dialog);
		Object control = xDlgContainer.getControl(componentId);
		return (XTextComponent) UnoRuntime.queryInterface(XTextComponent.class, control);
	}

	/** Returns a Combo box (XComboBox) from a dialog */
	public static XComboBox getCombobox(XDialog dialog, String componentId) {
		XControlContainer xDlgContainer = (XControlContainer) UnoRuntime.queryInterface(XControlContainer.class,
				dialog);
		Object control = xDlgContainer.getControl(componentId);
		return (XComboBox) UnoRuntime.queryInterface(XComboBox.class, control);
	}

	/** Returns a List box (XListBox) from a dialog */
	public static XListBox getListBox(XDialog dialog, String componentId) {
		XControlContainer xDlgContainer = (XControlContainer) UnoRuntime.queryInterface(XControlContainer.class,
				dialog);
		Object control = xDlgContainer.getControl(componentId);
		return (XListBox) UnoRuntime.queryInterface(XListBox.class, control);
	}

	/** Returns a label (XFixedText) from a dialog */
	public static XFixedText getLabel(XDialog dialog, String componentId) {
		XControlContainer xDlgContainer = (XControlContainer) UnoRuntime.queryInterface(XControlContainer.class,
				dialog);
		Object control = xDlgContainer.getControl(componentId);
		return (XFixedText) UnoRuntime.queryInterface(XFixedText.class, control);
	}

	/** Returns a tree (XTreeControl) from a dialog */
	public static XControl getTree(XDialog dialog, String componentId) {
		XControlContainer xDlgContainer = (XControlContainer) UnoRuntime.queryInterface(XControlContainer.class,
				dialog);
		XControl control = xDlgContainer.getControl(componentId);
		return (XControl) UnoRuntime.queryInterface(XControl.class, control);
	}

	public static XTreeControl getTreeControl(XDialog dialog, String componentId) {
		XControlContainer xDlgContainer = (XControlContainer) UnoRuntime.queryInterface(XControlContainer.class,
				dialog);
		XControl control = xDlgContainer.getControl(componentId);
		return (XTreeControl) UnoRuntime.queryInterface(XTreeControl.class, control);
	}

	public static void EnableButton(XDialog dialog, String componentId, boolean enable) {
		XControlContainer xDlgContainer = (XControlContainer) UnoRuntime.queryInterface(XControlContainer.class,
				dialog);
		// retrieve the control that we want to disable or enable
		XControl xControl = UnoRuntime.queryInterface(XControl.class, xDlgContainer.getControl(componentId));
		XPropertySet xModelPropertySet = UnoRuntime.queryInterface(XPropertySet.class, xControl.getModel());
		try {
			xModelPropertySet.setPropertyValue("Enabled", Boolean.valueOf(enable));
		} catch (IllegalArgumentException | UnknownPropertyException | PropertyVetoException
				| WrappedTargetException e) {
			return;
		}
	}

	/** Set the focus to an input field */
	public static void SetFocus(XTextComponent editField) {
		XWindow xControlWindow = UnoRuntime.queryInterface(XWindow.class, editField);
		xControlWindow.setFocus();
	}

	public static void setPosition(XDialog dialog, int posX, int posY) {
		XControlModel xDialogModel = UnoRuntime.queryInterface(XControl.class, dialog).getModel();
		XPropertySet xPropSet = UnoRuntime.queryInterface(XPropertySet.class, xDialogModel);
		try {
			xPropSet.setPropertyValue("PositionX", posX);
			xPropSet.setPropertyValue("PositionY", posY);
		} catch (com.sun.star.lang.IllegalArgumentException | UnknownPropertyException | PropertyVetoException
				| WrappedTargetException e) {
			return;
		}
	}

	public static Point getPosition(XDialog dialog) {
		int posX = 0;
		int posY = 0;
		XControlModel xDialogModel = UnoRuntime.queryInterface(XControl.class, dialog).getModel();
		XPropertySet xPropSet = UnoRuntime.queryInterface(XPropertySet.class, xDialogModel);
		try {
			posX = (int) xPropSet.getPropertyValue("PositionX");
			posY = (int) xPropSet.getPropertyValue("PositionY");
		} catch (UnknownPropertyException | WrappedTargetException e) {
		}
		return new Point(posX, posY);
	}

	public static void showInfoMessage(XComponentContext context, XDialog dialog, String message) {
		showMessageBox(context, dialog, MessageBoxType.INFOBOX, "Info", message);
	}

	public static void showWarningMessage(XComponentContext context, XDialog dialog, String message) {
		showMessageBox(context, dialog, MessageBoxType.WARNINGBOX, "Warnung", message);
	}

	public static void showErrorMessage(XComponentContext context, XDialog dialog, String message) {
		showMessageBox(context, dialog, MessageBoxType.ERRORBOX, "Fehler", message);
	}

	public static void showMessageBox(XComponentContext context, XDialog dialog, MessageBoxType type, String sTitle,
			String sMessage) {
		XToolkit xToolkit;
		try {
			xToolkit = UnoRuntime.queryInterface(XToolkit.class,
					context.getServiceManager().createInstanceWithContext("com.sun.star.awt.Toolkit", context));
		} catch (Exception e) {
			return;
		}
		XMessageBoxFactory xMessageBoxFactory = UnoRuntime.queryInterface(XMessageBoxFactory.class, xToolkit);
		XWindowPeer xParentWindowPeer = UnoRuntime.queryInterface(XWindowPeer.class, dialog);
		XMessageBox xMessageBox = xMessageBoxFactory.createMessageBox(xParentWindowPeer, type,
				com.sun.star.awt.MessageBoxButtons.BUTTONS_OK, sTitle, sMessage);
		if (xMessageBox == null)
			return;

		xMessageBox.execute();
	}

	// Checks if the name property of the window is one of the supported names and
	// returns
	// always a valid string or null
	public static String getWindowName(com.sun.star.awt.XWindow aWindow) throws com.sun.star.uno.Exception {
		if (aWindow == null)
			new com.sun.star.lang.IllegalArgumentException(
					"Method external_event requires that a window is passed as argument");

		// We need to get the control model of the window. Therefore the first step is
		// to query for it.
		XControl xControlDlg = (XControl) UnoRuntime.queryInterface(XControl.class, aWindow);

		if (xControlDlg == null)
			throw new com.sun.star.uno.Exception("Cannot obtain XControl from XWindow in method external_event.");
		// Now get model
		XControlModel xModelDlg = xControlDlg.getModel();

		if (xModelDlg == null)
			throw new com.sun.star.uno.Exception("Cannot obtain XControlModel from XWindow in method external_event.");

		// The model itself does not provide any information except that its
		// implementation supports XPropertySet which is used to access the data.
		XPropertySet xPropDlg = (XPropertySet) UnoRuntime.queryInterface(XPropertySet.class, xModelDlg);
		if (xPropDlg == null)
			throw new com.sun.star.uno.Exception("Cannot obtain XPropertySet from window in method external_event.");

		// Get the "Name" property of the window
		Object aWindowName = xPropDlg.getPropertyValue("Name");

		// Get the string from the returned com.sun.star.uno.Any
		String sName = null;
		try {
			sName = AnyConverter.toString(aWindowName);
		} catch (com.sun.star.lang.IllegalArgumentException ex) {
			ex.printStackTrace();
			throw new com.sun.star.uno.Exception("Name - property of window is not a string.");
		}

		// Eventually we can check if we this handler can "handle" this options page.
		// The class has a member m_arWindowNames which contains all names of windows
		// for which it is intended
		for (int i = 0; i < SupportedWindowNames.length; i++) {
			if (SupportedWindowNames[i].equals(sName)) {
				return sName;
			}
		}
		return null;
	}

}
