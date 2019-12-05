import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

import java.util.HashSet;
import java.util.Set;

public class ShiroRealm extends AuthorizingRealm {

    /**
     * 认证
     * @param authenticationToken
     * @return
     * @throws AuthenticationException
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        //通过令牌获取用户名
        String username = (String) authenticationToken.getPrincipal();
        //通过令牌获取密码,shiro自带一套加密解密的系统
        String password=new String((char[])authenticationToken.getCredentials());
        //模拟从数据库获取的数据
        User user = new User();
        user.setUsername("zhangsan");
        user.setPassword("123456");
        user.setStatus("1");   //0,1,2 代表的是不同的状态

        if(!username.equals(user.getUsername())){
            throw  new UnknownAccountException("用户名不存在！");
        }else if(!password.equals(user.getPassword())){
            throw new IncorrectCredentialsException("密码错误！");
        }else if(!"1".equals(user.getStatus())){
            throw new  LockedAccountException("用户被锁定！");
        }
        //当前类的名字：
        return new SimpleAuthenticationInfo(user,password,getName());

    }

    /**
     * 授权
     * @param principalCollection
     * @return
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {

        SimpleAuthorizationInfo simpleAuthorizationInfo = new SimpleAuthorizationInfo();
        //定义角色列表的集合
        Set<String> roles = new HashSet<>();
        roles.add("admin");
        Set<String>permission=new HashSet<String>();
        permission.add("user:create");
        permission.add("user:delete");
        permission.add("user:update");
        simpleAuthorizationInfo.setRoles(roles);
        simpleAuthorizationInfo.setStringPermissions(permission);

        return simpleAuthorizationInfo;
    }


}
