package com.sxt.shiro.realm;

import com.sxt.bean.User;
import com.sxt.service.UserService;
import org.apache.commons.lang3.StringUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;

public class ShiroRelam extends AuthorizingRealm {

    @Autowired
    private UserService userService;

    /**
     * 授权
     * @param principal
     * @return
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principal) {
        // 获取身份信息 通过用户名查询到对应的用户的角色和权限
        //获取到认证成功以后的用户帐号
        String account = (String) principal.getPrimaryPrincipal();
        // 根据身份信息从数据库中查询权限数据
        // 权限信息的对象
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        //将角色信息设置到AuthorizationInfo
        List<String> roles = userService.getUserRolesByAccount(account);
        info.addRoles(roles);
        List<String> permissions = userService.getUserPermissionsByAccount(account);
        info.addStringPermissions(permissions);
        return info;
    }

    /**
     * 认证
     * @param token
     * @return
     * @throws AuthenticationException
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        String account = (String) token.getPrincipal();
        User user = null;
        if(StringUtils.isNotBlank(account)){
            user = userService.getUserByAccount(account);
        }
        if(user == null){
            return null;
        }
        //用户不为空

        SimpleAuthenticationInfo simpleAuthenticationInfo = new SimpleAuthenticationInfo(account, user.getPassword(), ByteSource.Util.bytes(user.getSalt()), this.getName());
        return simpleAuthenticationInfo;
    }
}
