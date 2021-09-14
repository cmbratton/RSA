/**
 * Name: Colby Bratton
 */
package pki_environment;

import java.net.*;
import java.util.Scanner;
import java.io.*;

/**
 * Creates a server socket that may be connected to by PKIClient
 * to allow for encrypted messaging in a PKI Environment
 * @author Colby Bratton
 *
 */
public class PKIServer {

	//initialize socket and input output streams
	
	// socket for PKIServer
    private Socket socket = null; 
    // server socket for PKIServer, may be connected to by PKIClient
    private ServerSocket server = null; 
    
    private DataInputStream serverIn =  null; // server input from client
    private DataOutputStream serverOut = null; // server output to client
    private BufferedReader terminalInput = null; // local user input from terminal
    
    // RSA object instance to utilize RSA encryption, decryption,
    // and credential file commands
    private RSA serverRSA;
    
    /**
     * Constructor to establish a server that may be connected to by client
     * via server's IP address and designated port number. Instantiates
     * socket object as well as all input and output streams, and generates
     * a new RSA object instance for user.
     * @param port port utilized by PKIServer
     */
    public PKIServer(int port) 
    { 
        // starts PKIServer and waits for a connection 
        try
        { 
        	// open server socket to client
            server = new ServerSocket(port); 
            System.out.println("PKI Server started"); 
  
            System.out.println("Waiting for a compatible client ..."); 
  
            // accept compatible PKIClient connection
            socket = server.accept(); 
            System.out.println("PKI Client accepted"); 
  
            // takes input from PKIClient socket 
            serverIn = new DataInputStream(
            		new BufferedInputStream(socket.getInputStream()));  
            
            // sends output to PKIClient socket
            serverOut = new DataOutputStream(socket.getOutputStream());
            
            // takes local user input from terminal
            terminalInput = new BufferedReader(new InputStreamReader(System.in));   
            
            // new RSA instance for local user
            // stores all necessary values and methods for encryption, decryption,
            // and cred file operation
            serverRSA = new RSA();
        }
        catch (IOException ioe) // if input or output stream cannot be instantiated
        {
        	System.out.println(ioe);
        }
    } 

    /**
     * Provides environment for encrypted messaging. Allows user to utilize credential
     * file operations, choose the type of encryption they would like to use, and to
     * send messages over socket w/ encryption. Utilizes server socket for connection
     * with client.
     */
    public void PKISession()
    {    	 
    	// handle file operations separately
    	 credentialSelection();
    	 
    	 String message = ""; // message to be encrypted and sent over socket
         byte [] encryptedMessage; // message received from socket for decryption
         
         // contains string of encryption type user wants to utilize on message
         String encryptSelect; 
         
         // contains string of decryption type to be used on encryptedMessage
         String decryptSelect; 
         
         // keeps track of current state of messaging
         // terminates connection when false
         Boolean continueMessaging = true;
         
         // receives basic local user input from terminal
         // used for operation selection, not message input from terminal
         Scanner encTypeInput = new Scanner(System.in);
    	  
         // while true, continue messaging environment
    	 while (continueMessaging) 
         { 
         	System.out.printf("\nHow would you like to encrypt your message?\n"
         			+ "(C)onfidentiality, (A)uthentication, (B)oth, or (Q)uit?: ");
         	
         	// get desired encryption type from user
         	encryptSelect = encTypeInput.next();
         	//System.out.println(); // newline to make terminal easier to read
         	
         	if (encryptSelect.contentEquals("q")
         			|| encryptSelect.contentEquals("Q"))
         	{
         		// terminate messaging environment
         		continueMessaging = false;
         	}
         	else // keep messaging
         	{	
         		try
         		{ 	
         			// send encryption type to client
         			serverOut.writeUTF(encryptSelect);
         			// receiver decryption type from client
         			decryptSelect = serverIn.readUTF();
         			
// RECEIVE MESSAGE------------------------------------------------------------------------------------
         			// PKIServer receives message first
         			
         			// receive length of encrypted message from client
         			int messageLen = serverIn.readInt();
         			// receive encrypted message from client
         			encryptedMessage = new byte[messageLen];
         			serverIn.readFully(encryptedMessage, 0, encryptedMessage.length);
         			
         			// Confidential decryption
         			if (decryptSelect.contentEquals("c")
         					|| decryptSelect.contentEquals("C"))
         			{
         				message = new String(serverRSA.decryptConfidentiality(encryptedMessage));
         			}
         			// Authentication decryption
         			else if (decryptSelect.contentEquals("a")
         					|| decryptSelect.contentEquals("A"))
         			{
         				System.out.printf("Authentication Message!: ");
         				message = new String(serverRSA.decryptAuthentication(encryptedMessage));
         			}
         			// Confidential and Authentication decryption
         			else
         			{
         				System.out.printf("Authentication Message!: ");
         				message = new String(serverRSA.decryptBoth(encryptedMessage));
         			}
         			
         			// print decrypted message to terminal
         			System.out.println(message);
         			
// SEND MESSAGE---------------------------------------------------------------------------------------
         			// get message from terminal
         			message = terminalInput.readLine();
         			
         			// Confidential encryption
         			if (encryptSelect.contentEquals("c")
         					|| encryptSelect.contentEquals("C"))
         			{
         				encryptedMessage = serverRSA.encryptConfidentiality(message.getBytes());
         			}
         			// Authentication encryption
         			else if (encryptSelect.contentEquals("a")
         					|| encryptSelect.contentEquals("A"))
         			{
         				encryptedMessage = serverRSA.encryptAuthentication(message.getBytes());
         			}
         			// Confidential and Authentication encryption
         			else
         			{
         				encryptedMessage = serverRSA.encryptBoth(message.getBytes());
         			}
         			
         			// send message byte length to client
         			serverOut.writeInt(encryptedMessage.length);
         			// send encryptedMessage to client
         			serverOut.write(encryptedMessage); 
         		} 
         		catch(IOException i) 
         		{ 
         			System.out.println("Error sending or receiving message. Try again!"); 
         		}
         	}
         } 
         System.out.println("Closing connection"); 

         // close socket connection and all input/output streams
         try
         {
        	 encTypeInput.close(); // close operation input from terminal
        	 serverIn.close(); // close input from server
        	 serverOut.close(); // close output to server
        	 terminalInput.close(); // close message input from terminal
        	 socket.close(); // terminate PKIServer
         }
         catch (IOException ioe) // error closing socket or input/output stream(s)
         {
        	 System.out.println(ioe);
         }
    }
    
    /**
     * Environment for user to create or import credential files
     * for use with encrypted messaging. Provides framework for 
     * generation a file with particular name, and importing a 
     * file with a particular name.
     */
    public void credentialSelection()
    {
    	// keeps track of state of cred file operations
    	// if true, keep manipulating cred files
    	Boolean credSelect = true;
    	
    	// contains user selected cred file operation
        String optionSelect;
        
        // contains user specified name of cred file
        String credFileName;
        
        // takes local user input from terminal for
        // operation selection
        Scanner optionInput = new Scanner(System.in);
        
        // if true, keep manipulating cred files
        // if false, stop manipulating cred files
        while (credSelect == true)
        {
        	System.out.println("\nWhat would you like to do?");
        	System.out.println("(A) Create a personal credential file\n"
        			+ "(B) Input a remote user credential file\n"
        			+ "(C) Start sending and receiving messages");
        	
        	// get cred file operation from local user
        	optionSelect = optionInput.next();
        	
        	// Create a personal cred file
        	if (optionSelect.contentEquals("a")
        			|| optionSelect.contentEquals("A"))
        	{
        		System.out.printf("Input the name for your credential file: ");
        		
        		// get file name from local user
        		credFileName = optionInput.next(); 
        		serverRSA.createCredentialsFile(credFileName);
        	}
        	// Import a remote user cred file
        	else if (optionSelect.contentEquals("b")
        			|| optionSelect.contentEquals("B"))
        	{
        		System.out.println("Input the name of the credential file: ");
        		
        		// get file name from local user
        		credFileName = optionInput.next();
        		serverRSA.inputNewCredentialsFile(credFileName);
        	}
        	// End cred file manipulation
        	else if (optionSelect.contentEquals("c")
        			|| optionSelect.contentEquals("C"))
        	{
        		credSelect = false;
        		System.out.println("Starting encrypted messaging. "
        				+ "Client may send a message first.");
        	}
        	else
        	{
        		System.out.println("Invalid input! Please select again.");
        	}
        }
    }
    
    public static void main(String args[]) 
    { 
    	// open PKIServer on port 5000
        PKIServer server = new PKIServer(5000);
        // start a secure and encrypted messaging session (PKI Environment)
        server.PKISession();
    } 
}
