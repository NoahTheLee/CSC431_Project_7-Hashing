import java.io.File;
import java.io.FileInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Scanner;
import java.util.Set;

public class Hashing {

    public static void main(String[] args) throws Exception {
        // Scanner for various inputs. Nicer than declaring it each time
        Scanner scanner = new Scanner(System.in);

        // Set up some sets to store the hashes in
        Set<String> sha256Hashes = new HashSet<>();
        Set<String> sha1Hashes = new HashSet<>();
        Set<String> md5Hashes = new HashSet<>();

        // Decided to just make it loop forever instead of an exit input
        while (true) {
            System.out.println("Would you like to hash a String or File?");
            // EXTRA CREDIT IMPLEMENTATION OF ACCEPTING A FILE
            // Prompt for string or file
            boolean shouldHashString = fileOrString(scanner, new String[] { "String", "File" });

            // Set up an object to store the bytes
            byte[] bytesToHash;

            // Get string value
            if (shouldHashString) {
                // Prompt for string input.
                String targetString = confirmString(scanner, "string");
                // Store the unhashed bytes
                bytesToHash = targetString.getBytes();
            } else {
                // EXTRA CREDIT IMPLEMENTATION OF ACCEPTING A FILE
                // Prompt for file input.
                File targetFile = getFile(scanner);

                // Store the unhashed bytes
                // EXTRA CREDIT IMPLEMENTATION OF ACCEPTING A FILE
                bytesToHash = readBytesFromFile(targetFile);
            }

            // Compute the three different hashes.
            byte[][] hashes = doHash(bytesToHash);
            // Convert each hash byte array to its hexadecimal representation.
            String sha256Hex = byteToHex(hashes[0]);
            String sha1Hex = byteToHex(hashes[1]);
            String md5Hex = byteToHex(hashes[2]);

            // Check for collisions against the hexadecimal representation of all hashes
            if (sha256Hashes.contains(sha256Hex)) {
                System.out.println("COLLISION: SHA-256 hash already exists!");
            } else {
                // If we do not have a collision, add the hash to the respective set
                sha256Hashes.add(sha256Hex);
            }

            if (sha1Hashes.contains(sha1Hex)) {
                System.out.println("COLLISION: SHA-1 hash already exists!");
            } else {
                // If we do not have a collision, add the hash to the respective set
                sha1Hashes.add(sha1Hex);
            }

            if (md5Hashes.contains(md5Hex)) {
                System.out.println("COLLISION: MD5 hash already exists!");
            } else {
                // If we do not have a collision, add the hash to the respective set
                md5Hashes.add(md5Hex);
            }

            // Prompt to view all hashes
            System.out.print("Would you like to view all current hashes? (Y/[any]): ");
            if (scanner.nextLine().equalsIgnoreCase("Y")) {
                System.out.println("Current hashes:");
                System.out.println("SHA-256: " + sha256Hashes);
                System.out.println("SHA-1: " + sha1Hashes);
                System.out.println("MD5: " + md5Hashes);
            }
            // Separator
            System.out.println("----------------------------------------------------");
        }
    }

    // This function returns a two-dimensional array of byte arrays, each containing
    // the hash of the input bytes using SHA-256, SHA-1, and MD5.
    // It also prints the hexadecimal representation of each hash and provides
    // warnings about their security.
    public static byte[][] doHash(byte[] bytesToHash) throws NoSuchAlgorithmException {
        MessageDigest hasher;

        // Do SHA-256 hashing
        hasher = MessageDigest.getInstance("SHA-256");
        byte[] sha256Hash = hasher.digest(bytesToHash);
        System.out.println("SHA-256: " + byteToHex(sha256Hash));
        System.out.println(
                "INFO: SHA-256 is recommended for secure applications due to its strong collision resistance.");

        // Etc
        hasher = MessageDigest.getInstance("SHA-1");
        byte[] sha1Hash = hasher.digest(bytesToHash);
        System.out.println("SHA-1: " + byteToHex(sha1Hash));
        System.out.println("WARNING: SHA-1 is considered deprecated; avoid it in favor of stronger algorithms.");

        // Etc
        hasher = MessageDigest.getInstance("MD5");
        byte[] md5Hash = hasher.digest(bytesToHash);
        System.out.println("MD5: " + byteToHex(md5Hash));
        System.out.println(
                "WARNING: MD5 is insecure for cryptographic purposes and should only be used for non-critical integrity checks.");

        // Return the hashes
        return new byte[][] { sha256Hash, sha1Hash, md5Hash };
        // imma keep it a buck i'm proud of using a two-dimensional array legitimately
    }

    // Pick a file or string, checking to ensure the input is valid betwene the two
    public static boolean fileOrString(Scanner scanner, String[] options) {
        String input;

        System.out.print("Please enter String or File: ");
        input = scanner.nextLine();

        while (true) {

            if (input.equalsIgnoreCase(options[0])) {
                System.out.println("\n\n\n");
                return true;
            } else if (input.equalsIgnoreCase(options[1])) {
                System.out.println("\n\n\n");
                return false;
            } else {

                System.out.println("\n\n\n");
                System.out.print("Invalid input.\nPlease enter String or File: ");
                input = scanner.nextLine();
            }

        }
    }

    // EXTRA CREDIT IMPLEMENTATION OF ACCEPTING A FILE
    // Handle a file, targeting something local on the user's system
    public static File getFile(Scanner reader) throws Exception {

        String prompt = "file name or path";

        // Holder for the file type, we use this to check if the file exists
        File returnedFile;

        // Reuse the confirmString method to get the file name
        String fileName = confirmString(reader, prompt);

        // Try to create a file object from the string
        returnedFile = new File(fileName);

        // If the file does not exist, prompt the user to try again
        // Hurrah for fencepost method
        while (!returnedFile.exists()) {
            System.out.println("The file you entered does not exist.");

            System.out.println("\n\n\n");
            fileName = confirmString(reader, prompt);

            returnedFile = new File(fileName);
        }
        System.out.println("\n\n\n");

        // Print the file name and path
        System.out.println("The file \"" + returnedFile.toString() + "\" has been selected.");
        System.out.println("Its path is: " + returnedFile.getAbsolutePath() + "\n");

        return returnedFile;
    }

    // Simple function to double check a string, pretty much just to be nice :)
    public static String confirmString(Scanner reader, String prompt) {
        String returnString;

        while (true) {

            System.out.print("Please enter a " + prompt + ": ");
            returnString = reader.nextLine();
            System.out.println("\n\n\n");

            System.out.println("You entered: \"" + returnString + "\" as your " + prompt + ".");
            System.out.println("Are you satisfied with this string?");
            System.out.print("(Y to confirm, any key to retry): ");

            if (reader.nextLine().equalsIgnoreCase("Y")) {
                System.out.println("\n\n\n");
                return returnString;
            }
            System.out.println("\n\n\n");
        }
    }

    // Breaking this out so it can be a little less ugly
    // Converting byte array to hex string
    public static String byteToHex(byte[] bytes) {
        return HexFormat.of().formatHex(bytes);
    }

    // EXTRA CREDIT IMPLEMENTATION OF ACCEPTING A FILE
    // This was broken out for simplicity. Just pulls the bytes out of a file
    public static byte[] readBytesFromFile(File targetFile) throws Exception {
        byte[] returnData;
        try (FileInputStream iStream = new FileInputStream(targetFile)) {
            returnData = iStream.readAllBytes();
        }
        return returnData;
    }

}