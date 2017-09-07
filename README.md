# AuthorizePolicy
A custome policy of authorize on asp.net core 2.0
一个基于授权的自定义策略类型，要求asp.net core 2.0以上

#### 使用方法：
###### 1、在Stuartup.cs中
          public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvc();
            services.AddAuthorization(options =>
            {
                //这个集合模拟用户权限表,如果是
                var permission = new List<Permission> {
                              new Permission {  Url="/", Name="admin"},
                              new Permission {  Url="/home/permissionadd", Name="admin"},
                              new Permission {  Url="/", Name="system"},
                              new Permission {  Url="/home/contact", Name="system"}
                          };
                //如果第三个参数，是ClaimTypes.Role，上面集合的每个元素的Name为角色名称，如果ClaimTypes.Name，即上面集合的每个元素的Name为用户名
                var permissionRequirement = new PermissionRequirement("/denied", permission, ClaimTypes.Role);
                options.AddPolicy("Permission",
                          policy => policy.Requirements.Add(permissionRequirement));
            }).AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme).AddCookie(options => {
                options.LoginPath = new PathString("/login");
                options.AccessDeniedPath = new PathString("/denied");
            });
            //注入授权Handler
            services.AddSingleton<IAuthorizationHandler, PermissionHandler>();
        }
###### 2、在Controller中
    [Authorize(Policy = "Permission")]
    public class HomeController : Controller
    登录Action中
          //用户标识
          var identity = new ClaimsIdentity(CookieAuthenticationDefaults.AuthenticationScheme);
          //如果是基于角色的授权策略，这里要添加用户
          identity.AddClaim(new Claim(ClaimTypes.Name, user.UserName));
          //如果是基于角色的授权策略，这里要添加角色
          identity.AddClaim(new Claim(ClaimTypes.Role, user.Role));
          await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity));
