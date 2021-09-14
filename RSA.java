/**
 * Name: Colby Bratton
 */
package pki_environment;

import java.io.*;
import java.math.BigInteger;
import java.util.Random;

/**
 * Class to store and utilize RSA client/server's keys and
 * other data to perform encryption and decryption in a 
 * PKI environment. Offers encryption/decryption for confidentiality,
 * authentication, and both combined.
 * @author Colby Bratton
 *
 */
public class RSA {
	
	// determines number of bits in the values of p, q, n, pubKey, 
	// and priKey. Change be changed on the fly for testing purposes.
	private static final int BITLENGTH = 2048;
	
	// values p, q, n, and phi(n) to be used generate pubKey and to 
	// be used for encryption/decryption
	private BigInteger myP;
	private BigInteger myQ;
	private BigInteger myN;
	private BigInteger phiOfN;
		
	// public and private keys of local RSA user
	private BigInteger myPubKey; // e_A
	private BigInteger myPriKey; // d_A
		
	// p, q, and n of remote RSA user, used in encryption/decryption
	// p * q = n
	private BigInteger theirP;
	private BigInteger theirQ;
	private BigInteger theirN;
		
	// public key of remote RSA user
	private BigInteger theirPubKey; // e_B
 
	/**
	 * Default constructor to generate all key values for local RSA user
	 */
    public RSA()
    {
    	// random number used for generation of different key values
        Random r = new Random();
        
        // generation of local users different key values
        myP = BigInteger.probablePrime(BITLENGTH, r);
        myQ = BigInteger.probablePrime(BITLENGTH, r);
        myN = myP.multiply(myQ);
        phiOfN = myP.subtract(BigInteger.ONE).multiply(myQ.subtract(BigInteger.ONE));
        
        // generate public and private key for local user
        myPubKey = BigInteger.probablePrime(BITLENGTH / 2, r);
        while (phiOfN.gcd(myPubKey).compareTo(BigInteger.ONE) > 0 && myPubKey.compareTo(phiOfN) < 0)
        {
            myPubKey.add(BigInteger.ONE);
        }
        myPriKey = myPubKey.modInverse(phiOfN);
    }
 
    /**
     * Constructor used to initialize local user with premade key values
     * @param pubKey public key of local user
     * @param priKey private key of local user
     * @param n value of n for local user
     */
    public RSA(BigInteger pubKey, BigInteger priKey, BigInteger n)
    {
        this.myPubKey = pubKey;
        this.myPriKey = priKey;
        this.myN = n;
    }
    
    /**
     * Creates a .key file containing the local users p value, q value, and public key
     * @param credFileName name of the credential file to be created
     */
    public void createCredentialsFile(String credFileName)
    {
    	// generic File object to generate file output stream
    	File credFile;
    	
    	// check for file extension
    	if (credFileName.contains(".key"))
    	{
    		credFile = new File (credFileName);
    	}
    	else // if not found, add it
    	{
    		credFile = new File(credFileName + ".key");
    	}
    	
    	
    	
    	if (!credFile.exists()) // if file doesn't exist, create it
    	{
    		// open a file output stream
    		try (BufferedWriter userCredsOutput = new BufferedWriter(new FileWriter((credFile))))
    		{
    			// write local user's p, q, and public key to file as strings
    			userCredsOutput.write(myP.toString() + "\n");
    			userCredsOutput.write(myQ.toString() + "\n");
    			userCredsOutput.write(myPubKey.toString());
    			
    			userCredsOutput.close();
    		}
    		catch (IOException ioe) // if file output stream can't be created or opened, print warning message
    		{
    			System.out.println("There was an issue creating the file! Check file and try again!\n");
    		}
    	}
    	else // if file exists, print notice to user
    	{
    		System.out.println("Credentials file " + credFileName + " already exists.\n");
    	}
    }
    
    /**
     * Inputs a remote user credential file specified by the user. 
     * @param credFileName name of the remote user credential file to be input
     */
    public void inputNewCredentialsFile(String credFileName)
    {
    	// generic file Object to generate file input stream
    	File credFile;
    	
    	// check for file extension
    	if (credFileName.contains(".key"))
    	{
    		credFile = new File (credFileName);
    	}
    	else // if not found, add it
    	{
    		credFile = new File(credFileName + ".key");
    	}
    	
    	if (!credFile.exists()) // if file doesn't exist, print warning message
    	{
    		System.out.println("Requested file does not exist or cannot be found!");
    		System.out.println("Note: Make sure file is in PKI Environment directory.\n");
    	}
    	else // if file does exist, open it
    	{
    		// open a file input stream
    		try (BufferedReader userCredsInput = new BufferedReader(new FileReader(credFile)))
    		{
    			// input remote users p, q, and public key and store in this instance
    			theirP = new BigInteger(userCredsInput.readLine());
    			theirQ = new BigInteger(userCredsInput.readLine());
    			theirPubKey = new BigInteger(userCredsInput.readLine());
    			
    			userCredsInput.close();
    			
    			// generate remote users n value
    			theirN = theirP.multiply(theirQ);
    			
    			/*
    			 * Note: p, q, and public key must be written to file and read from file in that
    			 *       specific order to work with this program.
    			 *       Additionally, n is generated instead of read from file as a precaution
    			 *       in case portions of the file are read from an outside user.
    			 */
    		}
    		catch (IOException ioe) // if file can't be opened, print warning message
    		{
    			System.out.println("There was an issue reading the file. Check file and try again!\n");
    		}
    	}
    }
    
    /**
     * Encrypts a user provided message using a remote user's public key and n value
     * This is used for Confidentiality purposes
     * @param message message, in bytes, to be encrypted
     * @return byte form of encrypted message
     */
    public byte[] encryptConfidentiality(byte[] message)
    {
        return (new BigInteger(message)).modPow(theirPubKey, theirN).toByteArray();
    }
    
    /**
     * Encrypts a user provided message using the local users private key and n value
     * This is used for Authentication purposes, which provides no security
     * @param message message, in bytes, to be encrypted
     * @return byte form of encrypted message
     */
    public byte[] encryptAuthentication(byte[] message)
    {
    	return (new BigInteger(message)).modPow(myPriKey, myN).toByteArray();
    }
    
    /**
     * Encrypts a user provided message for both Confidentiality and Authentication
     * using a local user's private key and n value, and the remote user's public 
     * key and n value. Provides both security AND sender validation
     * @param message message, in bytes, to be encrypted
     * @return byte form of encrypted message
     */
    public byte[] encryptBoth(byte[] message)
    {
    	// if local user's n value is smaller than remote user's, use remote user's 
    	// private key and n first
    	if ((myN.compareTo(theirN)) == -1)
    	{
    		return ( (new BigInteger(message)).modPow(myPriKey, myN) ).modPow(theirPubKey, theirN).toByteArray();
    	}
    	
    	// if local user's n value is larger, use local user's public key and n first
    	else
    	{
    		return ( (new BigInteger(message)).modPow(theirPubKey, theirN) ).modPow(myPriKey, myN).toByteArray();
    	}
    }
 
    /**
     * Decrypts a remote user provided message using local user's private key and n value.
     * This is used to decrypt Confidential messages
     * This message may be turned back into a String in the main program
     * @param message message, in bytes, to be decrypted
     * @return byte form of the decrypted message
     */
    public byte[] decryptConfidentiality(byte[] message)
    {
    	return (new BigInteger(message)).modPow(myPriKey, myN).toByteArray();
    }
    
    /**
     * Decrypts a remote user provides message using remote user's public key and n value.
     * This is used to decrypt Authentication messages, and does NOT provide any form of 
     * security.
     * This message may be turned back into a String in the main program
     * @param message message, in bytes, to be decrypted
     * @return byte form of the decrypted message
     */
    public byte[] decryptAuthentication(byte[] message)
    {
    	return (new BigInteger(message)).modPow(theirPubKey, theirN).toByteArray();
    }
    
    /**
     * Decrypts a remote user provided message that utilizes Confidentiality and 
     * Authentication using the remote user's public key and n value, and the 
     * local user's private key and n value. Provides both security and sender
     * validation.
     * @param message message, in bytes, to be decrypted
     * @return byte form of the decrypted message
     */
    public byte[] decryptBoth(byte[] message)
    {
    	// if local user's n value is smaller than remote user's, use remote user's
    	// public key and n value first
    	if ((myN.compareTo(theirN)) == -1)
    	{
    		return ( (new BigInteger(message)).modPow(theirPubKey, theirN) ).modPow(myPriKey, myN).toByteArray();
    	}
    	// if local user's n value is larger, user local user's private key and
    	// n value first
    	else
    	{
    		return ( (new BigInteger(message)).modPow(myPriKey, myN) ).modPow(theirPubKey, theirN).toByteArray();
    	}
    }
}