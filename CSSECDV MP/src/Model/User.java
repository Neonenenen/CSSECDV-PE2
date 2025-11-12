package Model;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class User {
    private int id;
    private String username;
    private String password;
    private int role = 2;
    private int locked = 0;
    private String salt;

    public User(String username, String password){
        setUsername(username);
        setPassword(password);
    }
    
    public User(int id, String username, String password, int role, int locked){
        this.id = id;
        setUsername(username);
        setPassword(password);
        this.role = role;
        this.locked = locked;
    }
    
    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        if (username == null || username.isEmpty()){
            throw new IllegalArgumentException("Username cannot be empty");
        }
        if (username.length() < 3 || username.length() > 40){
            throw new IllegalArgumentException("Username must be between 3 and 40 characters");
        }
        if (!username.matches("^[A-Za-z0-9_.@-]+$")){
            throw new IllegalArgumentException("Username contains invalid characters");
        }
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.salt = generateSalt();
        this.password = hashPassword(password, this.salt);
    }

    public int getRole() {
        return role;
    }

    public void setRole(int role) {
        this.role = role;
    }

    public int getLocked() {
        return locked;
    }

    public void setLocked(int locked) {
        this.locked = locked;
    }

    // For Password Hashing
    private String generateSalt(){
        byte[] saltBytes = new byte[16];
        new SecureRandom().nextBytes(saltBytes);
        return Base64.getEncoder().encodeToString(saltBytes);
    }

    private String hashPassword(String password, String salt){
        try{
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(Base64.getDecoder().decode(salt));
            byte[] hashed = md.digest(password.getBytes());
            return Base64.getEncoder().encodeToString(hashed);
        }catch (NoSuchAlgorithmException e){
            throw new RuntimeException("SHA-256 not available", e);
        }
    }
}
