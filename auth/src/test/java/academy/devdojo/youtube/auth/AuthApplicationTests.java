package academy.devdojo.youtube.auth;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
@SpringBootTest
public class AuthApplicationTests {

    @Test
    public void contextLoads() {
    }

    // $2a$10$rRP1QH5Xm4uE6/dzGcYg.Otz5G8OaRz4xia8/WfAkzfJ5hWHKXM3.
    @Test
    public void test() {
        System.out.println(new BCryptPasswordEncoder().encode("devdojo"));
    }

}
