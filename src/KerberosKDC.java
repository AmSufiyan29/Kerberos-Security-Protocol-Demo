import java.io.*;
import java.security.SecureRandom;
import java.util.Date;

public class KerberosKDC {
    private final String IV = "00000000000000000000000000000000";
    private final String keyKDC = "366D5321346C2671615A6F3255216E52"; //Master KDC key
    private String[] users, hashedPasswords;
    private SecureRandom random;
    private AES aes;

    //constructor for KerberosKDC
    //reads encrypted password hashes from text file and decrypts them and stores hashes in an array
    public KerberosKDC() throws IOException {
        aes = new AES();
        random = new SecureRandom();
        File file = new File("C:\\Users\\AmSuf\\College\\S4Spring2022\\Computer Security(CS 492) - Spring 2022\\Final Project\\Kerberos\\src\\Users.txt");
        BufferedReader br = new BufferedReader(new FileReader(file));
        int numUsers = 0;
        while ((br.readLine()) != null) numUsers++; // get the number of users information stored in file
        users = new String[numUsers];
        hashedPasswords = new String[numUsers];
        br.close();

        String str;
        int currentEntry = 0, index;
        BufferedReader buffR = new BufferedReader(new FileReader(file));
        //retrieve usernames and encrypted hashed passwords associated with them
        while ((str = buffR.readLine()) != null) {
            index = str.indexOf(' ');
            users[currentEntry] = str.substring(0,index);
            hashedPasswords[currentEntry] = aes.decryptString(str.substring(index+1),keyKDC,IV);
            currentEntry++;
        }
    }

    //check if user exists and also get the index for their name in array
    int connUserIndex;
    private boolean userExists(String user) {
        connUserIndex = 0;
        for (String u: users) {
            if (u.equals(user))
                return true;
            connUserIndex++;
        }
        return false;
    }

    //used to make sure a byte in hex is represented by a leading zero if necessary
    private String validateSize(String input) {
        int size = input.length();
        while (size < 2) {
            input = '0' + input;
            size++;
        }
        return input;
    }

    //check if password hash is present in the data base aka text file and also note the index for it in the file
    int userIndex;
    private boolean isAuthenticated(String passwordHash) {
        userIndex = 0;
        for (String str: hashedPasswords) {
            if (str.equals(passwordHash))
                return true;
            userIndex++;
        }

        return false;
    }

    //user uses this to successfully login and get TGT
    public String requestTGT(String userKey) {
        if (!isAuthenticated(userKey)) {
            System.out.println("KDC: User not Authenticated\n");
            return "Not Authenticated";
        }
        byte[] bytes = new byte[16]; // 128 bits are converted to 16 bytes;
        random.nextBytes(bytes);
        String userSessionKey = "";
        for (byte b : bytes) {
            userSessionKey += validateSize(Integer.toHexString(Byte.toUnsignedInt(b)));
        }

        // create and encrypt TGT with user and sessionKey
        String TGT = (users[userIndex]+"," + userSessionKey);
        TGT = aes.encryptString(TGT,keyKDC,IV);

        String encryptedSessionAndTGT = (userSessionKey + ","+ TGT);
        System.out.println("KDC: session key and TGT, " + encryptedSessionAndTGT + "\n");
        encryptedSessionAndTGT = aes.encryptString(encryptedSessionAndTGT,userKey,IV);
        System.out.println("KDC: Encrypted session key and TGT sent, " + encryptedSessionAndTGT + "\n");

        return encryptedSessionAndTGT;
    }

    // prints a list of available users username can connect with
    public void availableUsers(String username) {
        System.out.println("\nUsers Available:");
        for (String u: users) {
            if (!u.equals(username))
                System.out.println(u);
        }
    }

    //used to get shared sessionkey and ticket to another user
    //REPLY = E(“Bob”, KAB, ticket to Bob, SA)
    //▫ ticket to Bob = E(“Alice”, KAB, KB)
    //• KDC gets SA from TGT to verify timestamp
    public String connectWith(String connUser, String TGT, String authenticator) {
        //check if the requested user exists and get their key
        if (!userExists(connUser))  {
            System.out.println("KDC: Requested user does not exist");
            return "Unknown User";
        }
        //decrypt TGT to get sessionKey and user
        String decryptedTGT = aes.decryptString(TGT,keyKDC,IV);
        String sessionKey = decryptedTGT.substring(decryptedTGT.length()-32);
        String user = decryptedTGT.substring(0,decryptedTGT.length()-33);

        //get current time stamp
        Date currentDate = new Date();
        long currTimestamp = currentDate.getTime();

        //use sessionKey to decrypt authenticator and check if request is fresh
        String decryptedAuthenticator =  aes.decryptString(authenticator,sessionKey,IV);
        long timestamp = Long.parseLong(decryptedAuthenticator);
        if ((currTimestamp - timestamp > 10)) {
            System.out.println("KDC: Request not fresh");
            return "Not Fresh";
        }

        //generate shared session key
        byte[] bytes = new byte[16]; // 128 bits are converted to 16 bytes;
        random.nextBytes(bytes);
        String sharedSessionKey = "";
        for (byte b : bytes) {
            sharedSessionKey += validateSize(Integer.toHexString(Byte.toUnsignedInt(b)));
        }

        //get connUser key
        String connUserKey = hashedPasswords[connUserIndex];

        //create ticket to connUser
        String ticketToConnUser = user+","+sharedSessionKey;
        ticketToConnUser = aes.encryptString(ticketToConnUser,connUserKey,IV);

        //REPLY = E(“Bob”, KAB, ticket to Bob, SA)
        String reply = connUser + "," + sharedSessionKey + "," + ticketToConnUser;
        System.out.println("\nKDC: user, shared session, ticketToUser; " + reply);
        reply = aes.encryptString(reply,sessionKey,IV);
        System.out.println("\nKDC: Encrypted (user, shared session, ticketToUser) sent; " + reply);
        return reply;
    }
}
