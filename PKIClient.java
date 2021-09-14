/**
 * Name: Colby Bratton
 */
package pki_environment;

import java.net.*;
import java.util.Scanner;
import java.io.*;

/**
 * Creates a client socket connection with PKIServer to allow for encrypted
 * messaging in a PKI Environment
 * @author Colby Bratton
 *
 */
public class PKIClient {
	
	// initialize socket and input output streams 
	
	// socket for PKIClient, connects to PKIServer
    private Socket socket = null; 
    
    private DataInputStream clientIn = null; // client input from server
    private DataOutputStream clientOut = null; // client output to server
    private BufferedReader terminalInput = null; // local user input from terminal
    
    // RSA object instance to utilize RSA encryption, decryption,
    // and credential file commands
    private RSA clientRSA;
  
    /**
     * Constructor to establish connection with server on provided IP address
     * and port number. Instantiates socket object as well as all input and 
     * output streams, and generates a new RSA object instance for user.
     * @param address IP address of PKIServer
     * @param port port utilized by PKIServer
     */
    public PKIClient(String address, int port) 
    {
        // establish a connection with PKIServer 
        try
        { 
        	// connect to PKIServer socket
            socket = new Socket(address, port); 
            System.out.println("Connected\n"); 
  
            // takes input from PKIServer socket
            clientIn = new DataInputStream(
            		new BufferedInputStream(socket.getInputStream()));
            
            // sends output to PKIServer socket
            clientOut = new DataOutputStream(socket.getOutputStream());
            
            // takes local user input from terminal
            terminalInput = new BufferedReader(new InputStreamReader(System.in));
            
            // new RSA instance for local user
            // stores all necessary values and methods for encryption, decryption,
            // and cred file operation
            clientRSA = new RSA();
        } 
        catch(UnknownHostException u) // if connection to server cannot be established
        { 
            System.out.println("Failed to connect to appropriate server!");
        } 
        catch(IOException i) // if input or output streams cannot be instantiated
        { 
            System.out.println(i); 
        } 
    } 
    
    /**
     * Provides environment for encrypted messaging. Allows user to utilize credential
     * file operations, choose the type of encryption they would like to use, and to
     * send messages over socket w/ encryption. Utilizes client socket for connection
     * with server.
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
        			// send encryption type to server
        			clientOut.writeUTF(encryptSelect);
        			// receive decryption type from server
        			decryptSelect = clientIn.readUTF();
        			
// SEND MESSAGE-------------------------------------------------------------------------------------
        			// PKIClient sends message first
        			message = terminalInput.readLine(); // get message from terminal
        			
        			// Confidential encryption
        			if (encryptSelect.contentEquals("c")
        					|| encryptSelect.contentEquals("C"))
        			{
        				encryptedMessage = clientRSA.encryptConfidentiality(message.getBytes());
        			}
        			// Authentication encryption
        			else if (encryptSelect.contentEquals("a")
        					|| encryptSelect.contentEquals("A"))
        			{
        				encryptedMessage = clientRSA.encryptAuthentication(message.getBytes());
        			}
        			// Confidential and Authentication encryption
        			else
        			{
        				encryptedMessage = clientRSA.encryptBoth(message.getBytes());
        			}
        			
        			// send message byte length to server
        			clientOut.writeInt(encryptedMessage.length);
        			// send encryptedMessage to server
        			clientOut.write(encryptedMessage);
				
// RECEIVE MESSAGE----------------------------------------------------------------------------------
        			// receive length of encrypted message from server
        			int messageLen = clientIn.readInt();
        			// receive encrypted message from server
        			encryptedMessage = new byte[messageLen];
        			clientIn.readFully(encryptedMessage, 0, encryptedMessage.length);
        			
        			// Confidential decryption
        			if (decryptSelect.contentEquals("c")
        					|| decryptSelect.contentEquals("C"))
        			{
        				message = new String(clientRSA.decryptConfidentiality(encryptedMessage));
        			}
        			// Authentication decryption
        			else if (decryptSelect.contentEquals("a")
        					|| decryptSelect.contentEquals("A"))
        			{
        				System.out.printf("Authentication Message!: ");
        				message = new String(clientRSA.decryptAuthentication(encryptedMessage));
        			}
        			// Confidential and Authentication decryption
        			else
        			{
        				System.out.printf("Authentication Message!: ");
        				message = new String(clientRSA.decryptBoth(encryptedMessage));
        			}
        			
        			// print decrypted message to terminal
        			System.out.println(message);
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
        	clientIn.close(); // close input from server
        	clientOut.close(); // close output to server
            terminalInput.close(); // close message input from terminal
            socket.close(); // terminate connection to PKIServer
        } 
        catch(IOException i) // error closing socket or input/output stream(s)
        { 
            System.out.println(i); 
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
        	System.out.println("What would you like to do?");
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
        		clientRSA.createCredentialsFile(credFileName);
        	}
        	// Import a remote user cred file
        	else if (optionSelect.contentEquals("b")
        			|| optionSelect.contentEquals("B"))
        	{
        		System.out.println("Input the name of the credential file: ");
        		
        		// get file name from local user
        		credFileName = optionInput.next();
        		clientRSA.inputNewCredentialsFile(credFileName);
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
    	// establish connection to PKIServer at designated IP and port
        PKIClient client = new PKIClient("192.168.56.1", 5000); 
        // start a secure and encrypted messaging session (PKI Environment)
        client.PKISession();
    } 
}
