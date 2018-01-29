
# AuthorizePolicy
A custome policy of authorize standard library for asp.net core 2.0

Blog：http://www.cnblogs.com/axzxs2001/p/7482777.html
#### Usage：
###### 1、Stuartup
```C#
          public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvc();
            services.AddAuthorization(options =>
            {
                var permission = new List<Permission> {
                              new Permission {  Url="/", Name="admin"},
                              new Permission {  Url="/home/permissionadd", Name="admin"},
                              new Permission {  Url="/", Name="system"},
                              new Permission {  Url="/home/contact", Name="system"}
                          };
                var permissionRequirement = new PermissionRequirement("/denied", permission, ClaimTypes.Role);
                options.AddPolicy("Permission",
                          policy => policy.Requirements.Add(permissionRequirement));
            }).AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme).AddCookie(options => {
                options.LoginPath = new PathString("/login");
                options.AccessDeniedPath = new PathString("/denied");
            });
         
            services.AddSingleton<IAuthorizationHandler, PermissionHandler>();
        }
```
###### 2、HomeController
```C#
        [Authorize(Policy = "Permission")]
        public class HomeController : Controller
```
###### 3、Login Action(Post)      
```C# 
          var identity = new ClaimsIdentity(CookieAuthenticationDefaults.AuthenticationScheme);    
          identity.AddClaim(new Claim(ClaimTypes.Name, user.UserName));      
          identity.AddClaim(new Claim(ClaimTypes.Role, user.Role));
          await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity));
```
