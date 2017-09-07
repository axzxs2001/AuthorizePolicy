using Microsoft.AspNetCore.Authorization;
using System.Collections.Generic;

namespace AuthorizePolicy
{
    /// <summary>
    /// 必要参数类
    /// </summary>
    public class PermissionRequirement : IAuthorizationRequirement
    {
        /// <summary>
        /// 用户权限集合
        /// </summary>
        public List<Permission> Permissions { get; private set; }
        /// <summary>
        /// 无权限action
        /// </summary>
        public string DeniedAction { get; set; }

        /// <summary>
        /// 认证授权类型
        /// </summary>
        public string ClaimType{ internal get; set; }
        /// <summary>
        /// 构造
        /// </summary>
        /// <param name="deniedAction">无权限action</param>
        /// <param name="userPermissions">用户权限集合</param>
        public PermissionRequirement(string deniedAction, List<Permission> permissions, string claimType)
        {
            ClaimType = claimType;
            DeniedAction = deniedAction;
            Permissions = permissions;
        }
    }
}
