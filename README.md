# AuthorizePolicy
A custome policy of authorize on asp.net core 2.0
一个基于授权的自定义策略类型，要求asp.net core 2.0以上

使用方法：
1、在Stuartup.cs中
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvc(); 
            services.AddAuthorization(options =>
            {
                var userPermission = new List<UserPermission> {
                              new UserPermission {  Url="/", UserName="gsw"},
                              new UserPermission {  Url="/home/permissionadd", UserName="gsw"},
                              new UserPermission {  Url="/", UserName="aaa"},
                              new UserPermission {  Url="/home/contact", UserName="aaa"}
                          };
                options.AddPolicy("Permission",
                          policy => policy.Requirements.Add(new PermissionRequirement("/denied", userPermission)));
            }).AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme).AddCookie(options =>{
                options.LoginPath = new PathString("/login");
                options.AccessDeniedPath = new PathString("/denied");
            });
            //注入授权Handler
            services.AddSingleton<IAuthorizationHandler, PermissionHandler>();
        }
