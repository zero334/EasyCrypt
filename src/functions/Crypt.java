package functions;

import java.awt.EventQueue;

import javax.swing.ButtonGroup;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPasswordField;
import javax.swing.JButton;

import java.awt.Toolkit;

import javax.swing.JTextArea;

import java.awt.Font;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;

import javax.swing.JRadioButton;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JCheckBox;
import javax.swing.JProgressBar;


public class Crypt {

	private JFrame frmFileCrypt;
	private JTextArea txtDragYourFile;
	private JButton btnStart;
	private JRadioButton rdbtnEncrypt;
	private JPasswordField passwordField;
	private JProgressBar progressBar;
	
	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					Crypt window = new Crypt();
					window.frmFileCrypt.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the application.
	 */
	public Crypt() {
		initialize();
		displayPath();
		crypt();
	}

	/**
	 * Initialize the contents of the frame.
	 */
	private void initialize() {
		frmFileCrypt = new JFrame();
		frmFileCrypt.setResizable(false);
		frmFileCrypt.setIconImage(Toolkit.getDefaultToolkit().getImage(Crypt.class.getResource("/resources/lock.png")));
		frmFileCrypt.setTitle("Easy Crypt - by zero334");
		frmFileCrypt.setBounds(100, 100, 450, 300);
		frmFileCrypt.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frmFileCrypt.getContentPane().setLayout(null);
		
		// Password lable
		JLabel lblPassword = new JLabel("Password:");
		lblPassword.setBounds(13, 14, 67, 14);
		frmFileCrypt.getContentPane().add(lblPassword);
		
		// Password field
		passwordField = new JPasswordField();
		final char darkCircle = 0x25cf;
		passwordField.setEchoChar(darkCircle);
		passwordField.setBounds(90, 11, 334, 20);
		frmFileCrypt.getContentPane().add(passwordField);
		
		// Start btn
		btnStart = new JButton("En/De Crypt");
		btnStart.setToolTipText("Start the crypting process");
		btnStart.setBounds(140, 228, 154, 23);
		frmFileCrypt.getContentPane().add(btnStart);
		
		txtDragYourFile = new JTextArea();
		txtDragYourFile.setFont(new Font("Arial Black", Font.PLAIN, 38));
		txtDragYourFile.setText("Drag your file here.");
		txtDragYourFile.setToolTipText("Drag your file here");
		txtDragYourFile.setEditable(false);
		txtDragYourFile.setBounds(13, 91, 411, 101);
		frmFileCrypt.getContentPane().add(txtDragYourFile);
		
		rdbtnEncrypt = new JRadioButton("Encrypt");
		rdbtnEncrypt.setSelected(true);
		rdbtnEncrypt.setBounds(13, 35, 76, 23);
		frmFileCrypt.getContentPane().add(rdbtnEncrypt);
		
		JRadioButton rdbtnDecrypt = new JRadioButton("Decrypt");
		rdbtnDecrypt.setBounds(13, 61, 76, 23);
		frmFileCrypt.getContentPane().add(rdbtnDecrypt);
		
		
		ButtonGroup btnGroupEnDeCrypt = new ButtonGroup();
		btnGroupEnDeCrypt.add(rdbtnEncrypt);
		btnGroupEnDeCrypt.add(rdbtnDecrypt);
		
		JCheckBox chckbxShowPassword = new JCheckBox("Show Password");
		chckbxShowPassword.addItemListener(new ItemListener() {
		    public void itemStateChanged(ItemEvent e) {// Show or hide Password
		        if (e.getStateChange() == ItemEvent.SELECTED) {
		        	passwordField.setEchoChar((char) 0);
		        } else {
		        	final char darkCircle = 0x25cf;
		        	passwordField.setEchoChar(darkCircle); // Default dark circle
		        }
		    }
		});
		
		
		chckbxShowPassword.setBounds(185, 38, 121, 23);
		frmFileCrypt.getContentPane().add(chckbxShowPassword);
		
		progressBar = new JProgressBar();
		progressBar.setBounds(13, 203, 411, 14);
		progressBar.setStringPainted(true);
		frmFileCrypt.getContentPane().add(progressBar);
	}
	
	
	private void displayPath() {

		new  FileDrop( txtDragYourFile, new FileDrop.Listener() {
		public void  filesDropped( java.io.File[] files ) {
			
			for( int i = 0; i < files.length; i++ ) {
				try {
					txtDragYourFile.setFont(new Font("Arial", Font.PLAIN, 13));
					txtDragYourFile.setText(null);
					txtDragYourFile.append(files[i].getCanonicalPath());
                }
                catch( java.io.IOException e ) {}
            }
	      }
	  });
	}


	private void updateStatusBar(String info, int progress) {
		progressBar.setString(info);
		progressBar.setValue(progress);
		progressBar.paint(progressBar.getGraphics());
	}


	private void crypt() {
		btnStart.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				
				String filePath = txtDragYourFile.getText(); // Get path from textField
				String password = new String(passwordField.getPassword());
				
				// Check if En or Decrypt
				if (rdbtnEncrypt.isSelected()) {
					try {
						
						//STATUS
						updateStatusBar("Starting encryption", 10);
						
						
						// File to be encrypted
						FileInputStream inFile;
						
						inFile = new FileInputStream(filePath);
						
						
						//STATUS
						updateStatusBar("Getting file", 20);
						
						
						// Get Name of the file
						File file = new File(filePath);
						String fileName = file.getName();
						fileName += ".des";

						// encrypted file
						FileOutputStream outFile = new FileOutputStream(fileName);

						//STATUS
						updateStatusBar("Generating salt", 30);
						
						// salt is used for encoding
						byte[] salt = new byte[8];
						SecureRandom secureRandom = new SecureRandom();
						secureRandom.nextBytes(salt);
						FileOutputStream saltOutFile = new FileOutputStream("salt.enc");
						saltOutFile.write(salt);
						saltOutFile.close();
	
						SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
						KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, 65536, 128);
						SecretKey secretKey = factory.generateSecret(keySpec);
						SecretKey secret = new SecretKeySpec(secretKey.getEncoded(), "AES");


						Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
						cipher.init(Cipher.ENCRYPT_MODE, secret);
						AlgorithmParameters params = cipher.getParameters();


						// iv adds randomness to the text and just makes the mechanism more
						// secure
						// used while initializing the cipher
						// file to store the iv
						
						//STATUS
						updateStatusBar("Generating iv", 40);
						
						FileOutputStream ivOutFile = new FileOutputStream("iv.enc");
						byte[] iv = params.getParameterSpec(IvParameterSpec.class).getIV();
						ivOutFile.write(iv);
						ivOutFile.close();
	
						//STATUS
						updateStatusBar("Starting File encryption - this may take some time", 50);
						
						//file encryption
						byte[] input = new byte[64];
						int bytesRead;
	
						while ((bytesRead = inFile.read(input)) != -1) {
							byte[] output = cipher.update(input, 0, bytesRead);
							if (output != null)
								outFile.write(output);
						}
	
						byte[] output = cipher.doFinal();
						if (output != null) {
							outFile.write(output);
						}
						
						//STATUS
						updateStatusBar("Cleaning up", 60);
						
						inFile.close();
						outFile.flush();
						outFile.close();
						
						//STATUS
						updateStatusBar("Packing files - this may take some time", 75);
						
						// Add file to archive
						String[] filesToZip = {fileName, "salt.enc", "iv.enc"};
						Zip.zip(filesToZip, "");
						
						//STATUS
						updateStatusBar("Sucess! Crypted file: crypted.crpt", 100);
					
					} catch (IOException | IllegalBlockSizeException | BadPaddingException | InvalidParameterSpecException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					
					
				} else {
					try {
						
						//STATUS
						updateStatusBar("Starting decryption", 10);
						
						String execPath = System.getProperty("user.dir"); // Get execution path

						
						//STATUS
						updateStatusBar("Unpacking - this may take some time", 30);
						
						// Unzip files
						Zip.unZip(filePath, execPath);
						
						
						//STATUS
						updateStatusBar("Getting encrpted file name", 40);
						
						// Get full file name
						String fullName = ExtensionFinder.findExtention(execPath, ".des");
						// Extract name - cut .des
						String[] words = fullName.split("\\.");
						final int wordsLength = words.length - 1;
						int buffer = 0;
						String finalFileName = "";
						while (buffer < wordsLength) {
							finalFileName += words[buffer] + '.';
							buffer++;
						}
						
						// Delete last character if it is a '.'
						if (finalFileName.length() > 0 && finalFileName.charAt(finalFileName.length() - 1) == '.') {
							finalFileName = finalFileName.substring(0, finalFileName.length() - 1);
						}
						
						//STATUS
						updateStatusBar("Reading the salt", 50);
						
						
						// reading the salt
						FileInputStream saltFis = new FileInputStream("salt.enc");
						byte[] salt = new byte[8];
						saltFis.read(salt);
						saltFis.close();
	
						
						//STATUS
						updateStatusBar("Reading the iv", 60);
						
						// reading the iv
						FileInputStream ivFis = new FileInputStream("iv.enc");
						byte[] iv = new byte[16];
						ivFis.read(iv);
						ivFis.close();
	
						SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
						KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, 65536, 128);
						SecretKey tmp = factory.generateSecret(keySpec);
						SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");
	
						
						//STATUS
						updateStatusBar("Decrypt file - this may take some time", 60);
						
						// file decryption
						Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
						cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(iv));
						FileInputStream fis = new FileInputStream(finalFileName + ".des");
						FileOutputStream fos = new FileOutputStream(finalFileName);
						byte[] in = new byte[64];
						int read;
						while ((read = fis.read(in)) != -1) {
							byte[] output = cipher.update(in, 0, read);
							if (output != null) {
								fos.write(output);
							}
						}
	
						byte[] output = cipher.doFinal();
						if (output != null) {
							fos.write(output);
						}
	
						fis.close();
						fos.flush();
						fos.close();
						
						//STATUS
						updateStatusBar("Sucess! - File Decrypted.", 100);
	
						// Cleanup
						String[] cryptFileNames = {"iv.enc", "salt.enc", finalFileName + ".des"};
						for(short iter = 0; iter < 3; iter++) {
							File cryptFiles = new File(cryptFileNames[iter]);
							cryptFiles.delete();
						}

					} catch (IOException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
					
			}
		});
		
	}
}
