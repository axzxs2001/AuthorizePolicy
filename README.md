# AuthorizePolicy
An ASP.NET Core middleware which implements custom authorization policy.

A blog post covering more details can be found at [my Chinese blog](http://www.cnblogs.com/axzxs2001/p/7482777.html).

#### Usage：
###### 1. Startup
```
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
###### 2. Controller
```
[Authorize(Policy = "Permission")]
public class HomeController : Controller
```
###### 3. Login Action 
```
var identity = new ClaimsIdentity(CookieAuthenticationDefaults.AuthenticationScheme);    
identity.AddClaim(new Claim(ClaimTypes.Name, user.UserName));      
identity.AddClaim(new Claim(ClaimTypes.Role, user.Role));
await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity));
```
