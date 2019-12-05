import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.junit.Test;

public class ShiroTest {

    @Test
    public  void get(){
        IniSecurityManagerFactory isma=new IniSecurityManagerFactory("classpath:shiro.ini");
        SecurityManager securityManager = isma.getInstance();
        SecurityUtils.setSecurityManager(securityManager);
        Subject subject=SecurityUtils.getSubject();
        UsernamePasswordToken token=new UsernamePasswordToken("zhangsan","123456");
        subject.login(token);
        System.out.println(subject.isAuthenticated());
        System.out.println("是否具有创建产品的权限："+subject.isPermitted("product:create"));
        System.out.println("是否具有创建用户的权限："+subject.isPermitted("user:create"));

        //查询用户是否具有某个角色的授权信息
        System.out.println("是否具有授权："+subject.hasRole("admin"));
        System.out.println("是否具有授权："+subject.hasRole("sadmin"));
        subject.logout();
        System.out.println("退出之后");
        System.out.println("是否具有创建产品的权限："+subject.isPermitted("product:create"));
        System.out.println("是否具有创建用户的权限："+subject.isPermitted("user:create"));

        //查询用户是否具有某个角色的授权信息
        System.out.println("是否具有授权："+subject.hasRole("admin"));
        System.out.println("是否具有授权："+subject.hasRole("sadmin"));


    }
}
