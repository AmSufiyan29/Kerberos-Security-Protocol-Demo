import java.io.IOException;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) throws IOException {
        boolean loginSuccessful = false;
        //creating a user
        User alice = new User();

        //getting login credentials from user
        Scanner scan = new Scanner(System.in);
        while(!loginSuccessful) {
            System.out.println("Enter your username: ");
            String username = scan.nextLine();
            System.out.println("Enter your password: ");
            String password = scan.nextLine();
            System.out.println();

            //Try to login and get TGT
            String result = alice.login(username,password);
            if (result.equals("Login Successful"))
                loginSuccessful = true;
        }
        System.out.println("\nLogin Successful");

        //print out a list of users you can connect with through kerberos
        alice.printAvailableUsers();

        //connect with another user
        System.out.println("\nWho do you want to connect with: ");
        String connectWith = scan.nextLine();
        alice.talkTo(connectWith);
    }


}


//Example valid login credentials
//Alice  StrongPassword
//Bob    StrongestPassword
//Carl   weakPass