import java.io.IOException;
import java.util.Date;

public class User {
    private final String IV = "00000000000000000000000000000000";
    private String TGT;
    private String sessionKey;
    private KerberosKDC kdc;
    private AES aes;
    private String name;

    public User() throws IOException {
        kdc = new KerberosKDC();
        aes = new AES();
    }

    public String login(String username, String password) {
        this.name = username;

        //deriving the users key from password
        String userKey = getUserKey(password);

        //requesting a TGT from KDC
        String tgtRequest = getTGT(userKey);

        //Check if tgt request was successful
        if (tgtRequest.equals("Not Authenticated")) {
            System.out.println("User: Could not get TGT\n");
            return "Login Failed";
        }
        else {
            //decrypting the response to TGT request to get session key and TGT
            String decryptedTgtRequest = aes.decryptString(tgtRequest,userKey,IV);
            sessionKey = decryptedTgtRequest.substring(0,32);
            TGT = decryptedTgtRequest.substring(33);
            System.out.println("User: Session Key received, " + sessionKey);
            System.out.println("User: TGT received, " + TGT);
        }
        return "Login Successful";
    }

    //Kerberos system derives user key from user password
    private String getUserKey(String userPassword) {
        MD5 md5 = new MD5();
        String userKey = md5.hash(userPassword);
        return userKey;
    }

    //requesting a TGT from KDC
    private String getTGT(String userKey) {
        return kdc.requestTGT(userKey);
    }

    //prints users available to talk to
    public void printAvailableUsers() {
        kdc.availableUsers(name);
    }

    //REQUEST = (TGT, authenticator)
    //▫ authenticator = E(timestamp, Sessionkey)
    public String talkTo(String connUser) {
        //get current time stamp for authenticator
        Date currentDate = new Date();
        long timestamp = currentDate.getTime();

        //create authenticator by encrypting timestamp with sessionKey
        String authenticator = aes.encryptString(Long.toString(timestamp),sessionKey,IV);
        //send kdc a request to connect
        String connectRequest = kdc.connectWith(connUser,TGT,authenticator);

        //REPLY = D(“Bob”, KAB, ticket to Bob; SA)
        String decryptedConnectRequest = aes.decryptString(connectRequest,sessionKey,IV);

        //get shared session key and ticket to Bob after decrypting
        String[] decrypted = decryptedConnectRequest.split(",");

        //get name of user we wanted to connect with
        String connectUser = decrypted[0];
        System.out.println("\nUser: Ticket to, " + connectUser + ", received");

        //get shared key that we have with user
        String sharedKey = decrypted[1];
        System.out.println("\nUser: shared key with " + connectUser + " received, " + sharedKey);

        //get ticket to user we wanted to connect with
        String ticketToUser = decrypted[2];
        System.out.println("\nUser: ticket to " + connectUser + " received, " + ticketToUser);

        return connectRequest;
    }


}
