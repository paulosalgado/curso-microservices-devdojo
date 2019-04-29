package academy.devdojo.youtube.auth;

import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
//@SpringBootTest
public class AuthApplicationTests {

    @Ignore
    @Test
    public void contextLoads() { }

    // $2a$10$vmhNa01EwTq8YqYJ09YV5uBIluda2Bjd7.zPTf3.DJ7HxhQAUcYs6
    @Ignore
    @Test
    public void generatePasswordEncoded() {
        System.out.println(new BCryptPasswordEncoder().encode("devdojo"));
    }

}
